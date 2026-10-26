//! Complete transient install intent and exclusion at the kernel deletion key.

use crate::outbound_binding::{validate_sa_policy_request, OutboundSaPolicyExpectation};
use crate::{PolicyParameters, SaParameters, XfrmError};

/// Complete install intent in the restricted sole-producer profile. Keys stay
/// in zeroizing model buffers; this request and its eventual receipt are never
/// serialized to an object journal.
#[derive(Clone)]
pub struct ScopedXfrmRequest {
    pub(crate) sa: SaParameters,
    pub(crate) policy: PolicyParameters,
    pub(crate) expectation: OutboundSaPolicyExpectation,
}
impl std::fmt::Debug for ScopedXfrmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedXfrmRequest(<redacted>)")
    }
}
impl ScopedXfrmRequest {
    /// Validate one ESP SA and its protective In/Out policy. Both use a nonzero
    /// full-mask mark and a nonzero reqid; the template SPI must be zero.
    /// Construction grants no kernel mutation or committed activation authority.
    pub fn new(sa: SaParameters, policy: PolicyParameters) -> Result<Self, XfrmError> {
        if !sa
            .mark
            .is_some_and(|mark| mark.is_exact_profile() && mark.value() != 0)
            || sa.request_id.is_none()
            || policy.templates.iter().any(|template| template.id.spi != 0)
        {
            return Err(XfrmError::invalid_config(
                "local_scope.request",
                "nonzero exact marks, reqid and SPI-zero templates are required",
            ));
        }
        let expectation =
            validate_sa_policy_request(&sa, &policy, policy.direction).map_err(|_| {
                XfrmError::invalid_config(
                    "local_scope.request",
                    "SA and policy do not match the restricted profile",
                )
            })?;
        if sa
            .auth
            .as_ref()
            .map(|(_, key)| key)
            .into_iter()
            .chain(sa.crypt.as_ref().map(|(_, key)| key))
            .chain(sa.aead.as_ref().map(|(_, key)| key))
            .any(|key| !key.is_empty() && key.as_bytes().iter().all(|byte| *byte == 0))
        {
            return Err(XfrmError::invalid_config(
                "local_scope.request",
                "keys must be distinguishable from redacted kernel readback",
            ));
        }
        crate::linux::validate_scoped_install_encoding(&sa, &policy)?;
        Ok(Self {
            sa,
            policy,
            expectation,
        })
    }

    /// Validate that this request can succeed `predecessor` for one flow.
    ///
    /// A Child-SA rekey successor keeps the exact flow identity: the policy
    /// lookup key (selector, direction, selector mark, interface ID), the SA
    /// outer selector, destination/protocol/source, lookup mark, interface ID
    /// and mode, the policy priority/action, the policy template selector,
    /// source address and mode, and the packet-marking presentation
    /// (`output_mark`, fixed outer DSCP) are unchanged. Only the SA SPI and the
    /// policy/SA request ID may differ, so the existing protective policy can
    /// be repointed to the successor SA in one atomic policy update while the
    /// predecessor SA remains installed. This keeps the rekeyed flow's
    /// scheduling and byte-level packet presentation identical.
    ///
    /// Construction of each request already validated its own profile.
    /// This does not reserve a key, grant committed activation authority or
    /// touch the kernel.
    /// # Errors
    /// [`XfrmError::StateMismatch`] `local_scope_successor_flow` when the two
    /// requests name different flows, or `local_scope_successor_identity` when
    /// the successor does not have a distinct SPI and request ID.
    pub fn validate_successor_of(&self, predecessor: &Self) -> Result<(), XfrmError> {
        let same_flow = self.policy.selector == predecessor.policy.selector
            && self.policy.direction == predecessor.policy.direction
            && self.policy.mark == predecessor.policy.mark
            && self.policy.if_id == predecessor.policy.if_id
            && self.sa.selector == predecessor.sa.selector
            && self.sa.id.destination == predecessor.sa.id.destination
            && self.sa.id.protocol == predecessor.sa.id.protocol
            && self.sa.source_address == predecessor.sa.source_address
            && self.sa.mark == predecessor.sa.mark
            && self.sa.if_id == predecessor.sa.if_id
            && self.sa.mode == predecessor.sa.mode
            && self.sa.output_mark == predecessor.sa.output_mark
            && self.sa.egress_dscp == predecessor.sa.egress_dscp
            && self.policy.priority == predecessor.policy.priority
            && self.policy.action == predecessor.policy.action
            && self.policy.templates.len() == predecessor.policy.templates.len()
            && self
                .policy
                .templates
                .iter()
                .zip(predecessor.policy.templates.iter())
                .all(|(successor, predecessor)| {
                    successor.id.destination == predecessor.id.destination
                        && successor.id.protocol == predecessor.id.protocol
                        && successor.id.spi == predecessor.id.spi
                        && successor.source_address == predecessor.source_address
                        && successor.mode == predecessor.mode
                });
        if !same_flow {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_flow",
            });
        }
        if self.sa.id.spi == predecessor.sa.id.spi
            || self.sa.request_id == predecessor.sa.request_id
        {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_identity",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fixture() -> (SaParameters, PolicyParameters) {
    use crate::*;
    let source = crate::IpAddress::Ipv4([192, 0, 2, 10]);
    let destination = crate::IpAddress::Ipv4([192, 0, 2, 20]);
    let sa = SaParameters {
        selector: XfrmSelector::new(source, destination, 0),
        id: XfrmId {
            destination,
            spi: 4096,
            protocol: 50,
        },
        source_address: source,
        request_id: crate::XfrmRequestId::new(99),
        auth: None,
        crypt: None,
        aead: Some((
            crate::AeadAlgorithm::rfc4106_gcm_aes(128),
            crate::KeyMaterial::new(vec![0x7b; 20]),
        )),
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: Some(XfrmLookupMark::full(77)),
        output_mark: None,
        if_id: Some(55),
        egress_dscp: None,
        tfc_pad: None,
    };
    let policy = PolicyParameters {
        selector: sa.selector.clone(),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        mark: sa.mark,
        if_id: sa.if_id,
        templates: vec![XfrmTemplate {
            id: XfrmId { spi: 0, ..sa.id },
            source_address: source,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
    };
    (sa, policy)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{XfrmDirection, XfrmLookupMark};
    #[test]
    fn request_requires_encodable_configuration_and_distinguishable_key_readback() {
        let (sa, policy) = fixture();
        let mut redacted = sa.clone();
        redacted.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(vec![0; 20]);
        assert!(ScopedXfrmRequest::new(redacted, policy.clone()).is_err());
        let mut malformed = sa.clone();
        malformed.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(vec![1; 3]);
        assert!(ScopedXfrmRequest::new(malformed, policy.clone()).is_err());
        let mut overlapping = sa.clone();
        let mut overlapping_policy = policy.clone();
        overlapping.mark = Some(XfrmLookupMark::new(0x10, 0xf0).unwrap());
        overlapping_policy.mark = overlapping.mark;
        assert!(ScopedXfrmRequest::new(overlapping, overlapping_policy).is_err());
    }
    #[test]
    fn fixed_dscp_request_defers_only_runtime_profile_validation() {
        let (mut sa, policy) = fixture();
        sa.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        ScopedXfrmRequest::new(sa.clone(), policy.clone())
            .expect("runtime supplies the reserved mark window");
        sa.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(vec![1; 3]);
        assert!(
            ScopedXfrmRequest::new(sa, policy).is_err(),
            "DSCP must not bypass encoding checks"
        );
    }
    #[test]
    fn restricted_request_refuses_allocating_templates_and_unmarked_or_zero_domains() {
        let (sa, policy) = fixture();
        for mark in [None, Some(XfrmLookupMark::full(0))] {
            let mut sa = sa.clone();
            let mut policy = policy.clone();
            sa.mark = mark;
            policy.mark = mark;
            assert!(
                ScopedXfrmRequest::new(sa, policy).is_err(),
                "unmarked or zero lookup domain must refuse"
            );
        }
        let mut nonzero_template = policy.clone();
        nonzero_template.templates[0].id.spi = sa.id.spi;
        assert!(
            ScopedXfrmRequest::new(sa.clone(), nonzero_template).is_err(),
            "ACQUIRE must never allocate a mature deletion key"
        );
        let mut no_reqid_sa = sa.clone();
        let mut no_reqid_policy = policy.clone();
        no_reqid_sa.request_id = None;
        no_reqid_policy.templates[0].request_id = None;
        assert!(ScopedXfrmRequest::new(no_reqid_sa, no_reqid_policy).is_err());
        for direction in [XfrmDirection::In, XfrmDirection::Out] {
            let mut policy = policy.clone();
            policy.direction = direction;
            ScopedXfrmRequest::new(sa.clone(), policy).unwrap();
        }
    }

    fn successor_request(predecessor: &ScopedXfrmRequest) -> ScopedXfrmRequest {
        let mut sa = predecessor.sa.clone();
        sa.id.spi = sa.id.spi.checked_add(1).unwrap();
        sa.request_id = Some(crate::XfrmRequestId::new(100).unwrap());
        sa.aead = Some((
            crate::AeadAlgorithm::rfc4106_gcm_aes(128),
            crate::KeyMaterial::new(vec![0x8c; 20]),
        ));
        let mut policy = predecessor.policy.clone();
        policy.templates[0].request_id = sa.request_id;
        ScopedXfrmRequest::new(sa, policy).unwrap()
    }

    #[test]
    fn successor_keeps_one_exact_flow_and_changes_the_sa_identity() {
        let (sa, policy) = fixture();
        let predecessor = ScopedXfrmRequest::new(sa, policy).unwrap();
        let successor = successor_request(&predecessor);
        successor.validate_successor_of(&predecessor).unwrap();

        let mut changed_selector = successor.sa.clone();
        changed_selector.selector.destination = crate::IpAddress::Ipv4([192, 0, 2, 21]);
        let mut changed_selector_policy = successor.policy.clone();
        changed_selector_policy.selector.destination = crate::IpAddress::Ipv4([192, 0, 2, 21]);
        let changed_selector =
            ScopedXfrmRequest::new(changed_selector, changed_selector_policy).unwrap();
        assert!(matches!(
            changed_selector.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_flow"
            })
        ));

        let mut changed_direction = successor.policy.clone();
        changed_direction.direction = XfrmDirection::In;
        let changed_direction =
            ScopedXfrmRequest::new(successor.sa.clone(), changed_direction).unwrap();
        assert!(matches!(
            changed_direction.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_flow"
            })
        ));

        let mut same_spi = successor.sa.clone();
        same_spi.id.spi = predecessor.sa.id.spi;
        let same_spi = ScopedXfrmRequest::new(same_spi, successor.policy.clone()).unwrap();
        assert!(matches!(
            same_spi.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_identity"
            })
        ));

        let same_request_id = successor_request(&predecessor);
        assert!(same_request_id.validate_successor_of(&predecessor).is_ok());
        let mut reused_request_id = successor_request(&predecessor);
        let mut reused_sa = reused_request_id.sa.clone();
        reused_sa.request_id = predecessor.sa.request_id;
        let mut reused_policy = reused_request_id.policy.clone();
        reused_policy.templates[0].request_id = predecessor.sa.request_id;
        reused_request_id = ScopedXfrmRequest::new(reused_sa, reused_policy).unwrap();
        assert!(matches!(
            reused_request_id.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_identity"
            })
        ));
    }

    #[test]
    fn successor_pins_flow_presentation_dscp_and_policy_priority() {
        let (sa, policy) = fixture();
        let predecessor = ScopedXfrmRequest::new(sa, policy).unwrap();
        let successor = successor_request(&predecessor);

        let mut changed_priority = successor.policy.clone();
        changed_priority.priority = predecessor.policy.priority.checked_add(1).unwrap();
        let changed_priority =
            ScopedXfrmRequest::new(successor.sa.clone(), changed_priority).unwrap();
        assert!(matches!(
            changed_priority.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_flow"
            })
        ));

        let mut changed_output_mark = successor.sa.clone();
        changed_output_mark.output_mark = Some(crate::XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        });
        let changed_output_mark =
            ScopedXfrmRequest::new(changed_output_mark, successor.policy.clone()).unwrap();
        assert!(matches!(
            changed_output_mark.validate_successor_of(&predecessor),
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_flow"
            })
        ));

        let mut changed_dscp = successor.sa.clone();
        changed_dscp.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        if let Ok(changed_dscp) = ScopedXfrmRequest::new(changed_dscp, successor.policy.clone()) {
            assert!(matches!(
                changed_dscp.validate_successor_of(&predecessor),
                Err(XfrmError::StateMismatch {
                    operation: "local_scope_successor_flow"
                })
            ));
        }
    }
    #[test]
    fn successor_reqid_preserves_inbound_overlap_and_outbound_selection() {
        for direction in [XfrmDirection::In, XfrmDirection::Out] {
            let (sa, mut policy) = fixture();
            policy.direction = direction;
            let previous = ScopedXfrmRequest::new(sa, policy).unwrap();
            let mut candidate = successor_request(&previous);
            if direction == XfrmDirection::In {
                candidate.sa.request_id = previous.sa.request_id;
                candidate.policy.templates[0].request_id = previous.sa.request_id;
            }
            let candidate = ScopedXfrmRequest::new(candidate.sa, candidate.policy).unwrap();
            candidate.validate_successor_of(&previous).unwrap();
            let mut wrong = candidate.clone();
            wrong.sa.request_id = if direction == XfrmDirection::In {
                crate::XfrmRequestId::new(100)
            } else {
                previous.sa.request_id
            };
            wrong.policy.templates[0].request_id = wrong.sa.request_id;
            let wrong = ScopedXfrmRequest::new(wrong.sa, wrong.policy).unwrap();
            assert!(matches!(
                wrong.validate_successor_of(&previous),
                Err(XfrmError::StateMismatch {
                    operation: "local_scope_successor_identity"
                })
            ));
        }
    }

    #[test]
    fn successor_cannot_change_the_outer_udp_encapsulation_path() {
        let (mut sa, policy) = fixture();
        sa.encap = Some(crate::UdpEncap::esp_in_udp(4500, 4500));
        let previous = ScopedXfrmRequest::new(sa, policy).unwrap();
        let candidate = successor_request(&previous);
        candidate.validate_successor_of(&previous).unwrap();
        for encap in [None, Some(crate::UdpEncap::esp_in_udp(4500, 62000))] {
            let mut changed = candidate.sa.clone();
            changed.encap = encap;
            let changed = ScopedXfrmRequest::new(changed, candidate.policy.clone()).unwrap();
            assert!(matches!(
                changed.validate_successor_of(&previous),
                Err(XfrmError::StateMismatch {
                    operation: "local_scope_successor_flow"
                })
            ));
        }
    }
}
