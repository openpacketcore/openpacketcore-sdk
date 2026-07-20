//! Deterministic conformance fake for the routing-stack adapter port.
//!
//! The fake implements [`RoutingStackAdapter`] with the exact contract every
//! real adapter must satisfy: after a successful apply it originates exactly
//! the accepted subset of the requested set and nothing else, mutations are
//! idempotent, and observations are scripted rather than synthesized. Every
//! mutation is recorded so conformance tests can prove delta-exact reconcile
//! and the absence of out-of-set origination under arbitrary call sequences.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

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

#[derive(Debug, Default)]
struct FakeState {
    originated: BTreeMap<RoutingDomainTag, BTreeSet<HostPrefix>>,
    apply_calls: Vec<RecordedAdvertisementApply>,
    withdraw_all_calls: Vec<RoutingDomainTag>,
    rejected_prefixes: BTreeSet<HostPrefix>,
    unreachable: bool,
    observations: Vec<PeerObservation>,
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

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl RoutingStackAdapter for ConformanceFakeRoutingStack {
    async fn apply_advertisement_set(
        &self,
        domain: RoutingDomainTag,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<BTreeMap<HostPrefix, PrefixApplyOutcome>, IpsecLbError> {
        let mut state = self.lock();
        if state.unreachable {
            return Ok(desired
                .iter()
                .map(|prefix| (*prefix, PrefixApplyOutcome::Unreachable))
                .collect());
        }
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
        // The port contract: originate exactly the accepted subset of the
        // requested set, never anything outside it.
        state.originated.insert(domain, originated.clone());
        state.apply_calls.push(RecordedAdvertisementApply {
            domain,
            desired: desired.clone(),
            originated_after: originated,
        });
        Ok(outcomes)
    }

    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError> {
        let mut state = self.lock();
        if state.unreachable {
            return Err(IpsecLbError::io(
                "fake_routing_stack_withdraw_all",
                std::io::Error::new(std::io::ErrorKind::NotConnected, "scripted unreachable"),
            ));
        }
        state.originated.remove(&domain);
        state.withdraw_all_calls.push(domain);
        Ok(())
    }

    async fn poll_observations(&self) -> Result<Vec<PeerObservation>, IpsecLbError> {
        let state = self.lock();
        if state.unreachable {
            return Err(IpsecLbError::io(
                "fake_routing_stack_poll",
                std::io::Error::new(std::io::ErrorKind::NotConnected, "scripted unreachable"),
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
