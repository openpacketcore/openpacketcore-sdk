//! Deterministic conformance fake for the routing-stack adapter port.
//!
//! The fake implements [`RoutingStackAdapter`] with the exact contract every
//! real adapter must satisfy: after a successful apply it originates exactly
//! the accepted subset of the requested set and nothing else, mutations are
//! idempotent, and observations are scripted rather than synthesized. Every
//! mutation is recorded so conformance tests can prove delta-exact reconcile
//! and the absence of out-of-set origination under arbitrary call sequences.
//!
//! Failure scripting models the ambiguous faults a real stack produces:
//! mid-apply disconnects before or after the mutation lands, partial
//! applies, and timeouts, plus an [`ApplyGate`] that lets a test cancel the
//! caller exactly after the side effect landed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::Notify;

use crate::error::IpsecLbError;
use crate::ownership::RoutingDomainTag;
use crate::routing::{
    HostPrefix, PeerObservation, PrefixApplyOutcome, PrefixRejectReason, RoutingStackAdapter,
    RoutingStackKind, RoutingStackProbe,
};

/// Recorded advertisement-set apply against the fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAdvertisementApply {
    /// Routing domain of the apply.
    pub domain: RoutingDomainTag,
    /// Exact desired set the service asked for.
    pub desired: BTreeSet<HostPrefix>,
    /// Exact originated set after the apply.
    pub originated_after: BTreeSet<HostPrefix>,
}

/// One effective adapter-side mutation, in order.
///
/// Only mutations that actually changed the fake's originated state are
/// recorded, so tests can assert the exact ordering of adapter effects
/// (for example that no apply lands after a drain's withdrawal).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordedStackMutation {
    /// An apply mutated the originated set.
    Apply {
        /// Routing domain of the apply.
        domain: RoutingDomainTag,
        /// Exact desired set the service asked for.
        desired: BTreeSet<HostPrefix>,
    },
    /// A withdrawal cleared the domain.
    WithdrawAll {
        /// Routing domain withdrawn.
        domain: RoutingDomainTag,
    },
}

/// Scripted ambiguous apply failure, consumed by the next apply call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FakeApplyFailure {
    /// The call fails with a timeout before any mutation lands.
    TimeoutBeforeApply,
    /// The call fails after originating only a deterministic subset (every
    /// second prefix) of the requested set.
    DisconnectAfterPartialApply,
    /// The call fails after the full mutation landed, modelling a
    /// disconnect between apply and acknowledgement.
    DisconnectAfterFullApply,
}

/// Gate that lets a test pause a scripted apply exactly after its side
/// effect landed and release it on demand.
#[derive(Debug)]
pub struct ApplyGate {
    landed: Arc<Notify>,
    release: Arc<Notify>,
}

impl ApplyGate {
    /// Wait until the gated apply's mutation has landed.
    pub async fn wait_landed(&self) {
        self.landed.notified().await;
    }

    /// Allow the gated apply to return.
    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[derive(Debug, Default)]
struct FakeState {
    originated: BTreeMap<RoutingDomainTag, BTreeSet<HostPrefix>>,
    apply_calls: Vec<RecordedAdvertisementApply>,
    withdraw_all_calls: Vec<RoutingDomainTag>,
    mutation_log: Vec<RecordedStackMutation>,
    rejected_prefixes: BTreeSet<HostPrefix>,
    unreachable: bool,
    observations: Vec<PeerObservation>,
    apply_failure: Option<FakeApplyFailure>,
    apply_gate: Option<ApplyGateShared>,
}

#[derive(Debug, Clone)]
struct ApplyGateShared {
    landed: Arc<Notify>,
    release: Arc<Notify>,
}

/// Deterministic conformance fake implementing [`RoutingStackAdapter`].
#[derive(Debug, Clone, Default)]
pub struct ConformanceFakeRoutingStack {
    state: Arc<Mutex<FakeState>>,
}

impl ConformanceFakeRoutingStack {
    /// Build an empty, reachable fake with no scripted rejections or peers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script one prefix to be rejected with
    /// [`PrefixRejectReason::PolicyDenied`] by future applies.
    pub fn reject_prefix(&self, prefix: HostPrefix) {
        self.lock().rejected_prefixes.insert(prefix);
    }

    /// Stop rejecting every prefix.
    pub fn clear_rejections(&self) {
        self.lock().rejected_prefixes.clear();
    }

    /// Script whole-stack unreachability: applies report per-prefix
    /// [`PrefixApplyOutcome::Unreachable`] without mutating, withdrawals and
    /// observation polls fail.
    pub fn set_unreachable(&self, unreachable: bool) {
        self.lock().unreachable = unreachable;
    }

    /// Script the next apply to fail ambiguously; consumed by one call.
    pub fn fail_next_apply(&self, failure: FakeApplyFailure) {
        self.lock().apply_failure = Some(failure);
    }

    /// Pause the next apply after its mutation landed until the gate is
    /// released, so a test can cancel the caller mid-flight.
    #[must_use]
    pub fn gate_next_apply(&self) -> ApplyGate {
        let gate = ApplyGateShared {
            landed: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        self.lock().apply_gate = Some(gate.clone());
        ApplyGate {
            landed: gate.landed,
            release: gate.release,
        }
    }

    /// Replace the scripted peer observations returned by the next polls.
    pub fn set_observations(&self, observations: Vec<PeerObservation>) {
        self.lock().observations = observations;
    }

    /// Return the exact set the fake currently originates for one domain.
    #[must_use]
    pub fn originated(&self, domain: RoutingDomainTag) -> BTreeSet<HostPrefix> {
        self.lock()
            .originated
            .get(&domain)
            .cloned()
            .unwrap_or_default()
    }

    /// Return every recorded apply call in order.
    #[must_use]
    pub fn apply_calls(&self) -> Vec<RecordedAdvertisementApply> {
        self.lock().apply_calls.clone()
    }

    /// Return every recorded domain withdrawal in order.
    #[must_use]
    pub fn withdraw_all_calls(&self) -> Vec<RoutingDomainTag> {
        self.lock().withdraw_all_calls.clone()
    }

    /// Return every effective adapter-side mutation in order.
    #[must_use]
    pub fn mutation_log(&self) -> Vec<RecordedStackMutation> {
        self.lock().mutation_log.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn io_error(
    operation: &'static str,
    kind: std::io::ErrorKind,
    message: &'static str,
) -> IpsecLbError {
    IpsecLbError::io(operation, std::io::Error::new(kind, message))
}

#[async_trait]
impl RoutingStackAdapter for ConformanceFakeRoutingStack {
    async fn apply_advertisement_set(
        &self,
        domain: RoutingDomainTag,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<BTreeMap<HostPrefix, PrefixApplyOutcome>, IpsecLbError> {
        enum Scripted {
            None,
            Fail(IpsecLbError),
        }

        let (scripted, gate) = {
            let mut state = self.lock();
            if state.unreachable {
                return Ok(desired
                    .iter()
                    .map(|prefix| (*prefix, PrefixApplyOutcome::Unreachable))
                    .collect());
            }
            let gate = state.apply_gate.take();
            let failure = state.apply_failure.take();
            let mut outcomes = BTreeMap::new();
            let mut originated = BTreeSet::new();
            for prefix in desired {
                if state.rejected_prefixes.contains(prefix) {
                    outcomes.insert(
                        *prefix,
                        PrefixApplyOutcome::Rejected(PrefixRejectReason::PolicyDenied),
                    );
                } else {
                    outcomes.insert(*prefix, PrefixApplyOutcome::Accepted);
                    originated.insert(*prefix);
                }
            }
            let scripted = match failure {
                None => {
                    // The port contract: originate exactly the accepted
                    // subset of the requested set, never anything outside it.
                    state.originated.insert(domain, originated.clone());
                    state.apply_calls.push(RecordedAdvertisementApply {
                        domain,
                        desired: desired.clone(),
                        originated_after: originated,
                    });
                    state.mutation_log.push(RecordedStackMutation::Apply {
                        domain,
                        desired: desired.clone(),
                    });
                    Scripted::None
                }
                Some(FakeApplyFailure::TimeoutBeforeApply) => Scripted::Fail(io_error(
                    "fake_routing_stack_apply",
                    std::io::ErrorKind::TimedOut,
                    "scripted timeout before apply",
                )),
                Some(FakeApplyFailure::DisconnectAfterPartialApply) => {
                    let partial: BTreeSet<HostPrefix> =
                        originated.iter().step_by(2).copied().collect();
                    state.originated.insert(domain, partial);
                    state.mutation_log.push(RecordedStackMutation::Apply {
                        domain,
                        desired: desired.clone(),
                    });
                    Scripted::Fail(io_error(
                        "fake_routing_stack_apply",
                        std::io::ErrorKind::NotConnected,
                        "scripted disconnect after partial apply",
                    ))
                }
                Some(FakeApplyFailure::DisconnectAfterFullApply) => {
                    state.originated.insert(domain, originated);
                    state.mutation_log.push(RecordedStackMutation::Apply {
                        domain,
                        desired: desired.clone(),
                    });
                    Scripted::Fail(io_error(
                        "fake_routing_stack_apply",
                        std::io::ErrorKind::NotConnected,
                        "scripted disconnect after full apply",
                    ))
                }
            };
            (scripted, gate)
        };

        if let Some(gate) = gate {
            gate.landed.notify_one();
            gate.release.notified().await;
        }
        match scripted {
            Scripted::None => {
                let outcomes = desired
                    .iter()
                    .map(|prefix| {
                        if self.lock().rejected_prefixes.contains(prefix) {
                            (
                                *prefix,
                                PrefixApplyOutcome::Rejected(PrefixRejectReason::PolicyDenied),
                            )
                        } else {
                            (*prefix, PrefixApplyOutcome::Accepted)
                        }
                    })
                    .collect();
                Ok(outcomes)
            }
            Scripted::Fail(error) => Err(error),
        }
    }

    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError> {
        let mut state = self.lock();
        // Record the attempt even when it fails so tests can prove the
        // watchdog is not head-of-line blocked.
        state.withdraw_all_calls.push(domain);
        if state.unreachable {
            return Err(io_error(
                "fake_routing_stack_withdraw_all",
                std::io::ErrorKind::NotConnected,
                "scripted unreachable",
            ));
        }
        state.originated.remove(&domain);
        state
            .mutation_log
            .push(RecordedStackMutation::WithdrawAll { domain });
        Ok(())
    }

    async fn poll_observations(&self) -> Result<Vec<PeerObservation>, IpsecLbError> {
        let state = self.lock();
        if state.unreachable {
            return Err(io_error(
                "fake_routing_stack_poll",
                std::io::ErrorKind::NotConnected,
                "scripted unreachable",
            ));
        }
        Ok(state.observations.clone())
    }

    async fn probe(&self) -> Result<RoutingStackProbe, IpsecLbError> {
        let reachable = !self.lock().unreachable;
        Ok(RoutingStackProbe {
            kind: RoutingStackKind::ConformanceFake,
            stack_reachable: reachable,
            mutation_ready: reachable,
            details: Some("deterministic conformance fake".to_owned()),
        })
    }
}
