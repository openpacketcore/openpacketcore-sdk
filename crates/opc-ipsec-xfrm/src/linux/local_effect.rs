//! Fresh receipt-bound reads used only by the registered scoped actor.

use super::*;
use crate::local_scope::effect::Readback;
use crate::ScopedXfrmRequest;

impl LinuxXfrmBackend {
    pub(crate) fn preflight_scoped_sa(&self, request: &ScopedXfrmRequest) -> Result<(), XfrmError> {
        let profile = self.prepare_dscp(&request.sa)?;
        let _encoded = encode_sa_info_inner(&request.sa, false, profile)?;
        Ok(())
    }
    pub(crate) async fn read_scoped_policy(
        &self,
        request: &ScopedXfrmRequest,
    ) -> Result<Readback, XfrmError> {
        match self
            .query_policy_for_outbound_binding(&request.policy)
            .await
        {
            Err(XfrmError::NotFound) => Ok(Readback::Absent),
            Ok(observed) if observed.parameters == request.policy => Ok(Readback::Exact),
            Ok(_) => Err(XfrmError::StateMismatch {
                operation: "local_scope_policy_receipt",
            }),
            Err(error) => Err(error),
        }
    }
    pub(crate) async fn read_scoped_sa(
        &self,
        request: &ScopedXfrmRequest,
    ) -> Result<Readback, XfrmError> {
        let expected = self.scoped_sa_identity(request)?;
        // This actor exclusively owns mature SA creation and holds the exact
        // deletion-key reservation. Admission requires nonzero SPI/full marks,
        // forbids ALLOCSPI and requires SPI-zero policy templates. An ACQUIRE
        // cannot occupy this nonzero-SPI key, including after its expiration.
        // A namespace-wide counted dump would instead stall on unrelated larval
        // states, which the SAD count includes but the mature-state dump omits.
        // Keep that strict dump for profile admission and generic callers.
        let body = match self.query_sa_for_outbound_binding(&request.sa).await {
            Ok(body) => body,
            Err(XfrmError::NotFound) => return Ok(Readback::Absent),
            Err(error) => return Err(error),
        };
        validate_scoped_sa(&body, request, &expected)?;
        Ok(Readback::Exact)
    }
    fn scoped_sa_identity(
        &self,
        request: &ScopedXfrmRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        let dscp = self
            .inner
            .dscp_config
            .as_ref()
            .map(LinuxXfrmDscpMarkingConfig::profile)
            .transpose()?;
        Ok(SaRelocationIdentity {
            selector: SaRelocationSelector::from_selector(&request.sa.selector),
            id: request.sa.id,
            source_address: request.sa.source_address,
            request_id: request.sa.request_id,
            mode: request.sa.mode,
            encap: request.sa.encap,
            mark: request.sa.mark,
            if_id: request.sa.if_id,
            output_mark: compose_output_mark(&request.sa, dscp)?,
        })
    }
    /// The caller retains the exact registry reservation across this read/delete.
    /// Generic remove_sa_exact remains unavailable: a snapshot alone is not this
    /// producer exclusion, policy-template restriction or full key comparison.
    pub(crate) async fn remove_scoped_sa(
        &self,
        request: &ScopedXfrmRequest,
        recheck: impl FnOnce() -> Result<(), XfrmError>,
    ) -> Result<(), XfrmError> {
        if self.read_scoped_sa(request).await? == Readback::Absent {
            return Ok(());
        }
        recheck()?;
        self.remove_sa(RemoveSaRequest {
            destination: request.sa.id.destination,
            protocol: request.sa.id.protocol,
            spi: request.sa.id.spi,
            mark: request.sa.mark,
        })
        .await
    }
    pub(crate) async fn remove_scoped_policy(
        &self,
        request: &ScopedXfrmRequest,
        recheck: impl FnOnce() -> Result<(), XfrmError>,
    ) -> Result<(), XfrmError> {
        if self.read_scoped_policy(request).await? == Readback::Absent {
            return Ok(());
        }
        recheck()?;
        self.remove_policy_exact(
            ExactRemovePolicyRequest::new(RemovePolicyRequest {
                selector: request.policy.selector.clone(),
                direction: request.policy.direction,
                mark: request.policy.mark,
            })
            .with_optional_if_id(request.policy.if_id),
        )
        .await
    }
}
fn validate_scoped_sa(
    body: &[u8],
    request: &ScopedXfrmRequest,
    expected: &SaRelocationIdentity,
) -> Result<(), XfrmError> {
    let observed =
        parse_outbound_sa_binding_snapshot(body, &request.expectation, Some(&request.sa))?;
    if &observed.identity != expected
        || observed.state.lifetime_config != request.sa.lifetime
        || observed.state.replay_window != request.sa.replay_window
    {
        return Err(XfrmError::StateMismatch {
            operation: "local_scope_sa_receipt",
        });
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scoped_sa_removal_refuses_every_changed_lifetime_limit() {
        let (sa, policy) = crate::local_scope::request::fixture();
        let request = ScopedXfrmRequest::new(sa, policy).unwrap();
        let expected = LinuxXfrmBackend::new()
            .scoped_sa_identity(&request)
            .unwrap();
        validate_scoped_sa(&encode_sa_info(&request.sa).unwrap(), &request, &expected).unwrap();
        for field in 0..6 {
            let mut changed = request.sa.clone();
            let limit = match field {
                0 => &mut changed.lifetime.soft_byte_limit,
                1 => &mut changed.lifetime.hard_byte_limit,
                2 => &mut changed.lifetime.soft_packet_limit,
                3 => &mut changed.lifetime.hard_packet_limit,
                4 => &mut changed.lifetime.soft_add_expires_seconds,
                _ => &mut changed.lifetime.hard_add_expires_seconds,
            };
            *limit = 71;
            assert!(
                validate_scoped_sa(&encode_sa_info(&changed).unwrap(), &request, &expected)
                    .is_err(),
                "changed lifetime field {field} cannot authorize removal"
            );
        }
    }

    #[test]
    fn exact_scoped_sa_keys_are_required_even_when_every_metadata_field_matches() {
        let (sa, policy) = crate::local_scope::request::fixture();
        let request = ScopedXfrmRequest::new(sa, policy).unwrap();
        let backend = LinuxXfrmBackend::new();
        let expected = backend.scoped_sa_identity(&request).unwrap();
        let body = encode_sa_info(&request.sa).unwrap();
        validate_scoped_sa(&body, &request, &expected).unwrap();
        for key in [vec![0; 20], vec![0x4c; 20]] {
            let mut changed = request.sa.clone();
            changed.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(key);
            let wire = encode_sa_info(&changed).unwrap();
            assert!(
                validate_scoped_sa(&wire, &request, &expected).is_err(),
                "redacted and changed keys cannot authorize removal"
            );
        }
        let mut changed = request.sa.clone();
        changed.request_id = XfrmRequestId::new(100);
        assert!(
            validate_scoped_sa(&encode_sa_info(&changed).unwrap(), &request, &expected).is_err()
        );
    }
}
