//! Complete Child-SA relocation intent and its bounded mutation program.

use std::{fmt, net::IpAddr};

use opc_proto_ikev2::nwu::mobike::{MigrationPermit, Path};

use crate::child_sa::{
    ChildSaPair, ChildSaSelectionLimits, ChildSaSelectionPlan, ChildSaTrafficIdentity,
};
use crate::{
    ChildSaInstalledRosterRequest, IpAddress, PolicyParameters, QueryPolicyRequest,
    RelocateSaRequest, SaParameters, SaRelocationDirection, SaRelocationEncap,
    SaRelocationIdentity, SaRelocationSelector, UdpEncap, XfrmAction, XfrmDirection, XfrmError,
    XfrmSaRelocationDurableError,
};

/// Complete original installed intent and a proposed authenticated outer path.
///
/// Construction grants no authority. Preparation additionally requires a live
/// MOBIKE permit, the exact previously associated installed publication, and
/// fresh readback of every resource including transient keys. Keep this intent
/// in protected caller storage for recovery; the SDK journal stores keyed
/// fingerprints only. Recovery may finish this exact previously admitted move
/// but never creates a live IKE or installed-roster publication.
#[derive(Clone)]
pub struct ChildSaRelocationIntent {
    /// Complete original roster, including receive-only rekey incarnations.
    pub current: ChildSaInstalledRosterRequest,
    /// New peer-to-local path validated by the authenticated COOKIE2 exchange.
    pub path: Path,
    /// Whether the final SAs use ESP-in-UDP with this path's directional ports.
    pub esp_udp: bool,
}

/// Value-free failure of complete-roster relocation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChildSaRelocationError {
    /// The live MOBIKE scope, generation, or authenticated target does not match.
    Authentication,
    /// Backend capability, validation, or current-state failure.
    Backend(XfrmError),
    /// Authenticated journal or namespace-writer fencing failure.
    Durable(XfrmSaRelocationDurableError),
}

impl fmt::Display for ChildSaRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication => f.write_str("child_sa_relocation_authentication"),
            Self::Backend(_) => f.write_str("child_sa_relocation_backend"),
            Self::Durable(_) => f.write_str("child_sa_relocation_durable"),
        }
    }
}
impl std::error::Error for ChildSaRelocationError {}
impl From<XfrmError> for ChildSaRelocationError {
    fn from(value: XfrmError) -> Self {
        Self::Backend(value)
    }
}
impl From<XfrmSaRelocationDurableError> for ChildSaRelocationError {
    fn from(value: XfrmSaRelocationDurableError) -> Self {
        Self::Durable(value)
    }
}
impl fmt::Debug for ChildSaRelocationIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChildSaRelocationIntent(<redacted>)")
    }
}

pub(crate) fn mismatch() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "child_sa_roster_relocation",
    }
}

fn unsupported() -> XfrmError {
    XfrmError::UnsupportedFeature {
        feature: "child_sa_roster_relocation_profile",
    }
}

fn ip(value: IpAddr) -> IpAddress {
    match value {
        IpAddr::V4(value) => IpAddress::Ipv4(value.octets()),
        IpAddr::V6(value) => IpAddress::Ipv6(value.octets()),
    }
}

pub(crate) fn identity(sa: &SaParameters) -> SaRelocationIdentity {
    SaRelocationIdentity {
        selector: SaRelocationSelector::from_selector(&sa.selector),
        id: sa.id,
        source_address: sa.source_address,
        request_id: sa.request_id,
        mode: sa.mode,
        encap: sa.encap,
        mark: sa.mark,
        if_id: sa.if_id,
        output_mark: sa.output_mark,
    }
}

pub(crate) fn policy_query(policy: &PolicyParameters) -> QueryPolicyRequest {
    let mut query = QueryPolicyRequest::new(policy.selector.clone(), policy.direction)
        .with_optional_if_id(policy.if_id);
    if let Some(mark) = policy.mark {
        query = query.with_mark(mark);
    }
    query
}

pub(crate) struct SaMove {
    pub old: SaParameters,
    pub new: SaParameters,
    pub policy: PolicyParameters,
    pub request: RelocateSaRequest,
}

pub(crate) struct PolicyMove {
    pub old: PolicyParameters,
    pub new: PolicyParameters,
    pub block: Option<PolicyParameters>,
}

#[derive(Clone, Copy)]
pub(crate) enum Step {
    Sa(usize),
    Policy { index: usize, phase: u8 },
}

pub(crate) struct Program {
    pub updated: ChildSaInstalledRosterRequest,
    pub sas: Vec<SaMove>,
    pub policies: Vec<PolicyMove>,
    pub steps: Vec<Step>,
}

impl ChildSaRelocationIntent {
    pub(crate) fn fingerprints(
        &self,
        key: crate::durable_object::CanonicalMacKey<'_>,
        updated: &ChildSaInstalledRosterRequest,
    ) -> Result<
        crate::durable_relocation::DurableRelocationFingerprints,
        XfrmSaRelocationDurableError,
    > {
        use crate::durable_object::authenticate_install_request;
        use crate::{InstallPolicyRequest, InstallSaRequest, XfrmObjectInstallRequest};
        let roster_mac = |roster: &ChildSaInstalledRosterRequest| {
            let mut mac = key.begin(b"opc-childsa-relocation-roster-v1\0");
            mac.update(&(roster.pairs.len() as u64).to_be_bytes());
            for pair in &roster.pairs {
                mac.update(&pair.pair.child().get().to_be_bytes());
                mac.update(&pair.pair.incarnation().get().to_be_bytes());
                mac.update(&[u8::from(pair.outbound_policy.is_some())]);
                let mut resources = vec![
                    XfrmObjectInstallRequest::Sa(InstallSaRequest {
                        parameters: pair.inbound_sa.clone(),
                    }),
                    XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
                        parameters: pair.inbound_policy.clone(),
                    }),
                    XfrmObjectInstallRequest::Sa(InstallSaRequest {
                        parameters: pair.outbound_sa.clone(),
                    }),
                ];
                if let Some(policy) = &pair.outbound_policy {
                    resources.push(XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
                        parameters: policy.clone(),
                    }));
                }
                for request in resources {
                    let digest = authenticate_install_request(
                        key,
                        b"opc-childsa-relocation-member-v1\0",
                        &request,
                    )
                    .map_err(|_| XfrmSaRelocationDurableError::Malformed)?;
                    mac.update(&digest);
                }
            }
            mac.update(&(roster.plan.classes().len() as u64).to_be_bytes());
            for binding in roster.plan.classes() {
                mac.update(&binding.class().get().to_be_bytes());
                mac.update(&binding.child().get().to_be_bytes());
            }
            mac.update(&roster.plan.default_child().get().to_be_bytes());
            Ok::<_, XfrmSaRelocationDurableError>(*mac.finalize())
        };
        let deletion_identity = roster_mac(&self.current)?;
        let mut mac = key.begin(b"opc-childsa-relocation-complete-request-v1\0");
        mac.update(&deletion_identity);
        mac.update(&roster_mac(updated)?);
        mac.update(&self.path.source().port().to_be_bytes());
        mac.update(&self.path.destination().port().to_be_bytes());
        mac.update(&[u8::from(self.esp_udp)]);
        Ok(crate::durable_relocation::DurableRelocationFingerprints {
            deletion_identity,
            relocation_request: *mac.finalize(),
        })
    }

    pub(crate) fn matches_permit(
        &self,
        permit: &MigrationPermit,
    ) -> Result<(), ChildSaRelocationError> {
        if permit.path() != self.path || permit.esp_udp_encapsulation() != self.esp_udp {
            return Err(ChildSaRelocationError::Authentication);
        }
        Ok(())
    }

    pub(crate) fn program(&self) -> Result<Program, XfrmError> {
        self.current.validate_relocation_intent()?;
        // An SDK resource bound, not an IKE or 3GPP limit. Every pair, including
        // a receive-only incarnation, participates in the same journal record.
        if self.current.pairs.len() > 8 {
            return Err(unsupported());
        }
        let first = &self.current.pairs[0].inbound_sa;
        let old_peer = first.source_address;
        let old_local = first.id.destination;
        let mut updated = self.current.clone();
        let mut sas = Vec::new();
        let mut policies = Vec::<PolicyMove>::new();
        for (original, next) in self.current.pairs.iter().zip(&mut updated.pairs) {
            // Every outbound incarnation must be covered by its selected
            // child's exact full-mark block; a receive-only SA cannot silently
            // escape that block through a different selector or scope.
            let selected = self
                .current
                .pairs
                .iter()
                .find(|pair| {
                    pair.pair.child() == original.pair.child() && pair.outbound_policy.is_some()
                })
                .ok_or_else(mismatch)?;
            let selected_policy = selected.outbound_policy.as_ref().ok_or_else(mismatch)?;
            if original.outbound_sa.selector != selected.outbound_sa.selector
                || original.outbound_sa.mark != selected.outbound_sa.mark
                || original.outbound_sa.if_id != selected.outbound_sa.if_id
            {
                return Err(unsupported());
            }
            for (old, new, direction, old_policy, new_policy) in [
                (
                    &original.inbound_sa,
                    &mut next.inbound_sa,
                    XfrmDirection::In,
                    &original.inbound_policy,
                    Some(&mut next.inbound_policy),
                ),
                (
                    &original.outbound_sa,
                    &mut next.outbound_sa,
                    XfrmDirection::Out,
                    original.outbound_policy.as_ref().unwrap_or(selected_policy),
                    next.outbound_policy.as_mut(),
                ),
            ] {
                let inbound = direction == XfrmDirection::In;
                let (source, destination) = if inbound {
                    (old_peer, old_local)
                } else {
                    (old_local, old_peer)
                };
                if old.source_address != source
                    || old.id.destination != destination
                    || old.egress_dscp.is_some()
                {
                    return Err(unsupported());
                }
                let path = if inbound {
                    self.path
                } else {
                    self.path.reversed()
                };
                new.source_address = ip(path.source().ip());
                new.id.destination = ip(path.destination().ip());
                new.encap = self.esp_udp.then_some(UdpEncap {
                    encap_type: crate::UDP_ENCAP_ESPINUDP,
                    source_port: path.source().port(),
                    destination_port: path.destination().port(),
                });
                if identity(old) == identity(new) {
                    return Err(unsupported());
                }
                let request = RelocateSaRequest {
                    current: identity(old),
                    new_source_address: new.source_address,
                    new_destination: new.id.destination,
                    encap: match (old.encap, new.encap) {
                        (_, Some(encap)) => SaRelocationEncap::Set(encap),
                        (Some(_), None) => SaRelocationEncap::Remove,
                        (None, None) => SaRelocationEncap::Preserve,
                    },
                    direction: if inbound {
                        SaRelocationDirection::Inbound
                    } else {
                        SaRelocationDirection::OutboundBlockPolicyInstalled
                    },
                };
                crate::model::validate_relocate_sa_request(&request)?;
                // Receive-only outbound readback still needs its own concrete
                // expected SPI; the selected child's policy is only its block
                // coverage proof, never that incarnation's SA expectation.
                let mut sa_policy = old_policy.clone();
                sa_policy.templates[0] = crate::XfrmTemplate {
                    id: old.id,
                    source_address: old.source_address,
                    request_id: old.request_id,
                    mode: old.mode,
                };
                sas.push(SaMove {
                    old: old.clone(),
                    new: new.clone(),
                    policy: sa_policy,
                    request,
                });
                if let Some(new_policy) = new_policy {
                    new_policy.templates[0].id.destination = new.id.destination;
                    new_policy.templates[0].source_address = new.source_address;
                    let existing = policies
                        .iter()
                        .find(|policy| policy_query(&policy.old) == policy_query(old_policy));
                    if let Some(existing) = existing {
                        if existing.old != *old_policy || existing.new != *new_policy {
                            return Err(unsupported());
                        }
                    } else {
                        let block = (!inbound).then(|| {
                            let mut block = old_policy.clone();
                            block.action = XfrmAction::Block;
                            block.templates.clear();
                            block
                        });
                        policies.push(PolicyMove {
                            old: old_policy.clone(),
                            new: new_policy.clone(),
                            block,
                        });
                    }
                }
            }
            next.pair = ChildSaPair::new(
                original.pair.child(),
                original.pair.incarnation(),
                ChildSaTrafficIdentity::new(
                    next.inbound_sa.id,
                    next.inbound_sa.mark,
                    next.inbound_sa.if_id,
                )
                .map_err(|_| mismatch())?,
                ChildSaTrafficIdentity::new(
                    next.outbound_sa.id,
                    next.outbound_sa.mark,
                    next.outbound_sa.if_id,
                )
                .map_err(|_| mismatch())?,
                original.pair.outbound_use(),
            );
        }
        updated.plan = ChildSaSelectionPlan::new(
            updated.pairs.iter().map(|pair| pair.pair.clone()).collect(),
            self.current.plan.classes().to_vec(),
            self.current.plan.default_child(),
            ChildSaSelectionLimits {
                max_pairs: 8,
                max_classes: 256,
            },
        )
        .map_err(|_| mismatch())?;
        updated.validate_relocation_intent()?;
        let mut steps = Vec::new();
        for (index, policy) in policies.iter().enumerate() {
            if policy.block.is_some() {
                steps.push(Step::Policy { index, phase: 1 });
            }
        }
        steps.extend((0..sas.len()).map(Step::Sa));
        for (index, policy) in policies.iter().enumerate() {
            if policy.block.is_none() && policy.old != policy.new {
                steps.push(Step::Policy { index, phase: 2 });
            }
        }
        for (index, policy) in policies.iter().enumerate() {
            if policy.block.is_some() {
                steps.push(Step::Policy { index, phase: 2 });
            }
        }
        Ok(Program {
            updated,
            sas,
            policies,
            steps,
        })
    }
}
