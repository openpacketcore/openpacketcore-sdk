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
}

#[cfg(test)]
pub(crate) fn fixture() -> (SaParameters, PolicyParameters) {
    use crate::*;
    let source = IpAddress::Ipv4([192, 0, 2, 10]);
    let destination = IpAddress::Ipv4([192, 0, 2, 20]);
    let sa = SaParameters {
        selector: XfrmSelector::new(source, destination, 0),
        id: XfrmId {
            destination,
            spi: 4096,
            protocol: 50,
        },
        source_address: source,
        request_id: XfrmRequestId::new(99),
        auth: None,
        crypt: None,
        aead: Some((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![0x7b; 20]),
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
}
