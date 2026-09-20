//! Actor-fenced publication of an exactly read-back Child-SA selection roster.
//!
//! The caller still owns IKE authentication, packet classification and exclusive
//! namespace-wide XFRM writer access. Publication reads installed state; it does
//! not install resources, authenticate packets or authorize endpoint relocation.

use std::{fmt, sync::Arc};

use crate::child_sa::{
    ChildSaOutboundSelection, ChildSaOutboundUse, ChildSaPair, ChildSaSelectionPlan,
    ChildSaTrafficIdentity,
};
use crate::namespace::NamespaceActorBinding;
use crate::outbound_binding::{validate_sa_policy_request, OutboundSaPolicyExpectation};
use crate::{
    LinuxXfrmBackend, OutboundSaBindingError, PolicyParameters, SaParameters, XfrmAction,
    XfrmDirection, XfrmError, XfrmMode, XfrmTemplate,
};

const MAX_PAIRS: usize = 32;
const MAX_CLASSES: usize = 256;

/// Transient key-bearing installed-state expectations for one declared pair.
///
/// Both SAs must exist. Every incarnation has an inbound allow policy; several
/// overlapping incarnations may share an identical request-ID-pinned inbound
/// policy. Only the selected outbound incarnation has an outbound policy, and
/// that policy must pin its concrete SPI. The SDK does not retain key material
/// in the resulting publication.
pub struct ChildSaInstalledPairRequest {
    /// Exact pair declaration, including its caller-assigned incarnation.
    pub pair: ChildSaPair,
    /// Expected installed inbound SA, including transient keys for readback.
    pub inbound_sa: SaParameters,
    /// Expected installed inbound allow policy.
    pub inbound_policy: PolicyParameters,
    /// Expected installed outbound SA, including transient keys for readback.
    pub outbound_sa: SaParameters,
    /// Concrete-SPI outbound allow policy, present exactly for selected pairs.
    pub outbound_policy: Option<PolicyParameters>,
}

/// Complete ordered installed-state request for one actor's current roster.
///
/// This bounded profile admits at most 32 pairs and 256 caller classes, tunnel
/// mode, exact lookup marks, one inbound policy per pair and one outbound policy
/// per selected child. Selected children require distinct full-mask outbound
/// marks so overlapping selectors remain distinguishable. The caller applies
/// the returned child's mark to its classified traffic. Unmarked outbound
/// selection and implicit wildcard-SPI preference are outside this profile.
///
/// Construction grants no installed or packet authority. Resources must first
/// be installed and any durable recovery/adoption completed through the existing
/// lifecycle APIs, before acquiring a [`ChildSaRosterUpdate`].
pub struct ChildSaInstalledRosterRequest {
    /// Validated class/default selection intentions.
    pub plan: ChildSaSelectionPlan,
    /// Every pair's resources, in exactly the plan's order.
    pub pairs: Vec<ChildSaInstalledPairRequest>,
}

/// Affine update ticket bound to one actor and its current writer generation.
///
/// Every admitted XFRM mutation or roster publication invalidates older tickets.
/// There is no public constructor and this ticket cannot be cloned. Acquire it
/// after installing resources, then consume it in the publication call.
pub struct ChildSaRosterUpdate {
    actor: NamespaceActorBinding,
    generation: u64,
}

/// Opaque, key-free publication of a complete installed Child-SA roster.
///
/// Clones refer to the same generation. Every admitted actor mutation, failed
/// current-state readback or replacement publication retires that generation.
/// After process loss, read back and publish anew; caller labels or serialized
/// generation numbers cannot reconstruct this capability. At most one roster
/// is current on an actor. Foreign/raw writers must be excluded by deployment.
///
/// ```compile_fail
/// let forged = opc_ipsec_xfrm::InstalledChildSaRoster {};
/// ```
#[derive(Clone)]
pub struct InstalledChildSaRoster {
    actor: NamespaceActorBinding,
    state: Arc<PublishedRoster>,
}

impl InstalledChildSaRoster {
    /// Process-local generation for correlation only; never authority by itself.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.state.generation
    }
}

/// Exact selected child after a fresh readback of the complete published roster.
///
/// This is a point-in-time installed-state result, not an ESP packet receipt or
/// a lock held across subsequent application sends. Callers serialize their
/// classification/send operation with all namespace writers. A later mutation
/// cannot be made safe by retaining this result.
pub struct InstalledChildSaSelection {
    pair: ChildSaPair,
    generation: u64,
}

impl InstalledChildSaSelection {
    /// Exact selected pair, including the concrete outbound SPI and lookup mark.
    #[must_use]
    pub const fn pair(&self) -> &ChildSaPair {
        &self.pair
    }

    /// Publication generation observed by this readback, for correlation only.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    )+};
}

redacted_debug!(
    ChildSaInstalledPairRequest,
    ChildSaInstalledRosterRequest,
    ChildSaRosterUpdate,
    InstalledChildSaRoster,
    InstalledChildSaSelection
);

struct RetainedPair {
    inbound: OutboundSaPolicyExpectation,
    outbound: OutboundSaPolicyExpectation,
    selected: bool,
}

struct PublishedRoster {
    generation: u64,
    plan: ChildSaSelectionPlan,
    pairs: Vec<RetainedPair>,
}

fn invalid(reason: &'static str) -> XfrmError {
    XfrmError::invalid_config("installed_child_sa_roster", reason)
}

fn stale() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "installed_child_sa_roster_generation",
    }
}

fn map_readback(error: OutboundSaBindingError) -> XfrmError {
    match error {
        OutboundSaBindingError::Readback { source } => source,
        _ => XfrmError::StateMismatch {
            operation: "installed_child_sa_roster_readback",
        },
    }
}

fn identity_matches(identity: ChildSaTrafficIdentity, sa: &SaParameters) -> bool {
    identity.id() == sa.id && identity.query().mark == sa.mark && identity.if_id() == sa.if_id
}

impl ChildSaInstalledRosterRequest {
    fn validate(&self) -> Result<Vec<RetainedPair>, XfrmError> {
        if self.pairs.len() > MAX_PAIRS || self.plan.classes().len() > MAX_CLASSES {
            return Err(invalid("capacity exceeded"));
        }
        if self.pairs.len() != self.plan.pairs().len() {
            return Err(invalid("incomplete pair roster"));
        }
        let mut retained = Vec::with_capacity(self.pairs.len());
        for (index, request) in self.pairs.iter().enumerate() {
            if request.pair != self.plan.pairs()[index]
                || !identity_matches(request.pair.inbound(), &request.inbound_sa)
                || !identity_matches(request.pair.outbound(), &request.outbound_sa)
            {
                return Err(invalid("pair resource identity mismatch"));
            }
            for sa in [&request.inbound_sa, &request.outbound_sa] {
                if sa.mode != XfrmMode::Tunnel
                    || sa.source_address.is_unspecified()
                    || sa.replay_window == 0
                    || (sa.auth.is_none() && sa.aead.is_none())
                {
                    return Err(invalid("SA outside authenticated tunnel profile"));
                }
            }
            let selected = request.pair.outbound_use() == ChildSaOutboundUse::Selected;
            if selected != request.outbound_policy.is_some() {
                return Err(invalid("outbound policy eligibility mismatch"));
            }
            if !selected {
                let current = self
                    .pairs
                    .iter()
                    .find(|candidate| {
                        candidate.pair.child() == request.pair.child()
                            && candidate.pair.outbound_use() == ChildSaOutboundUse::Selected
                    })
                    .ok_or_else(|| invalid("selected child missing"))?;
                if request.outbound_sa.selector != current.outbound_sa.selector
                    || request.outbound_sa.mark != current.outbound_sa.mark
                    || request.outbound_sa.if_id != current.outbound_sa.if_id
                {
                    return Err(invalid("receive-only outbound policy identity differs"));
                }
            }
            // Receive-only predecessors still require exact SA readback but
            // must not introduce a competing outbound allow policy. This
            // synthetic policy is used solely to build a key-free expectation;
            // it is never read as installed or issued to the kernel.
            let sa = &request.outbound_sa;
            let absent_policy = PolicyParameters {
                selector: sa.selector.clone(),
                direction: XfrmDirection::Out,
                action: XfrmAction::Allow,
                priority: 0,
                templates: vec![XfrmTemplate {
                    id: sa.id,
                    source_address: sa.source_address,
                    request_id: sa.request_id,
                    mode: sa.mode,
                }],
                mark: sa.mark,
                if_id: sa.if_id,
            };
            let outbound_policy = request.outbound_policy.as_ref().unwrap_or(&absent_policy);
            if selected {
                let Some(mark) = sa.mark else {
                    return Err(invalid("selected outbound mark required"));
                };
                if self.pairs[..index].iter().any(|prior| {
                    prior.pair.outbound_use() == ChildSaOutboundUse::Selected
                        && prior.outbound_sa.mark == Some(mark)
                }) {
                    return Err(invalid("selected outbound marks overlap"));
                }
                if outbound_policy.templates.len() != 1
                    || outbound_policy.templates[0].id.spi != sa.id.spi
                {
                    return Err(invalid("selected outbound SPI must be concrete"));
                }
            }
            let inbound = validate_sa_policy_request(
                &request.inbound_sa,
                &request.inbound_policy,
                XfrmDirection::In,
            )
            .map_err(|_| invalid("inbound SA policy mismatch"))?;
            let outbound = validate_sa_policy_request(sa, outbound_policy, XfrmDirection::Out)
                .map_err(|_| invalid("outbound SA policy mismatch"))?;
            retained.push(RetainedPair {
                inbound,
                outbound,
                selected,
            });
        }
        Ok(retained)
    }
}

/// Actor-owned and bounded: one current publication, no ticket registry and no
/// retained keys. Exhaustion permanently closes this actor's publication scope.
pub(crate) struct ChildSaRosterRegistry {
    generation: Option<u64>,
    current: Option<Arc<PublishedRoster>>,
}

impl Default for ChildSaRosterRegistry {
    fn default() -> Self {
        Self {
            generation: Some(1),
            current: None,
        }
    }
}

impl ChildSaRosterRegistry {
    pub(crate) fn invalidate(&mut self) {
        self.current = None;
        self.generation = self.generation.and_then(|value| value.checked_add(1));
    }

    pub(crate) fn begin(
        &self,
        actor: &NamespaceActorBinding,
    ) -> Result<ChildSaRosterUpdate, XfrmError> {
        Ok(ChildSaRosterUpdate {
            actor: actor.clone(),
            generation: self.generation.ok_or(XfrmError::Unavailable)?,
        })
    }

    pub(crate) async fn publish(
        &mut self,
        actor: &NamespaceActorBinding,
        backend: &LinuxXfrmBackend,
        update: ChildSaRosterUpdate,
        request: ChildSaInstalledRosterRequest,
    ) -> Result<InstalledChildSaRoster, XfrmError> {
        if update.actor != *actor || Some(update.generation) != self.generation {
            return Err(stale());
        }
        // Burn the ticket and withdraw the predecessor before any readback.
        // A failed or lost reply never leaves an older publication usable.
        self.invalidate();
        let generation = self.generation.ok_or(XfrmError::Unavailable)?;
        let pairs = request.validate()?;
        for (retained, supplied) in pairs.iter().zip(&request.pairs) {
            backend
                .read_child_sa_binding(&retained.inbound, Some(&supplied.inbound_sa), true)
                .await
                .map_err(map_readback)?;
            backend
                .read_child_sa_binding(
                    &retained.outbound,
                    Some(&supplied.outbound_sa),
                    retained.selected,
                )
                .await
                .map_err(map_readback)?;
        }
        let state = Arc::new(PublishedRoster {
            generation,
            plan: request.plan,
            pairs,
        });
        self.current = Some(Arc::clone(&state));
        Ok(InstalledChildSaRoster {
            actor: actor.clone(),
            state,
        })
    }

    pub(crate) async fn select(
        &mut self,
        actor: &NamespaceActorBinding,
        backend: &LinuxXfrmBackend,
        roster: &InstalledChildSaRoster,
        selection: ChildSaOutboundSelection,
    ) -> Result<InstalledChildSaSelection, XfrmError> {
        if roster.actor != *actor
            || self.generation != Some(roster.state.generation)
            || !self
                .current
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &roster.state))
        {
            return Err(stale());
        }
        let pair = roster
            .state
            .plan
            .select_outbound(selection)
            .map_err(|_| invalid("unknown outbound class"))?
            .clone();
        for retained in &roster.state.pairs {
            let result = async {
                backend
                    .read_child_sa_binding(&retained.inbound, None, true)
                    .await?;
                backend
                    .read_child_sa_binding(&retained.outbound, None, retained.selected)
                    .await?;
                Ok::<(), OutboundSaBindingError>(())
            }
            .await;
            if let Err(error) = result {
                self.invalidate();
                return Err(map_readback(error));
            }
        }
        Ok(InstalledChildSaSelection {
            pair,
            generation: roster.state.generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::NetworkNamespaceBinding;

    #[test]
    fn exhausted_actor_generation_never_wraps_or_reissues_an_update_ticket() {
        let actor = NamespaceActorBinding::new(NetworkNamespaceBinding::for_test(1, 2));
        let mut registry = ChildSaRosterRegistry {
            generation: Some(u64::MAX - 1),
            current: None,
        };
        assert_eq!(registry.begin(&actor).unwrap().generation, u64::MAX - 1);
        registry.invalidate();
        assert_eq!(registry.begin(&actor).unwrap().generation, u64::MAX);
        for _ in 0..3 {
            registry.invalidate();
            assert!(registry.begin(&actor).is_err());
        }
    }
}
