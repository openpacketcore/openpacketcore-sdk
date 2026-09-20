//! Readback-driven, prefix-recoverable execution of one whole-roster program.

use async_trait::async_trait;

#[cfg(test)]
pub(crate) mod tests;

use crate::child_sa_relocation::{
    identity, mismatch, policy_query, PolicyMove, Program, SaMove, Step,
};
use crate::outbound_binding::validate_sa_policy_request;
use crate::{
    LinuxXfrmBackend, PolicyParameters, QuerySaRequest, RekeyPolicyRequest, XfrmBackend, XfrmError,
};

#[async_trait]
pub(crate) trait RelocationIo: Send + Sync {
    async fn sa_is_new(&self, resource: &SaMove) -> Result<bool, XfrmError>;
    async fn policy(&self, resource: &PolicyMove) -> Result<PolicyParameters, XfrmError>;
    async fn move_sa(&self, resource: &SaMove) -> Result<(), XfrmError>;
    async fn put_policy(&self, policy: &PolicyParameters) -> Result<(), XfrmError>;
}

fn sa_query(sa: &crate::SaParameters) -> QuerySaRequest {
    let mut query = QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi);
    if let Some(mark) = sa.mark {
        query = query.with_mark(mark);
    }
    query
}

#[async_trait]
impl RelocationIo for LinuxXfrmBackend {
    async fn sa_is_new(&self, resource: &SaMove) -> Result<bool, XfrmError> {
        let old = self
            .query_sa_relocation_identity(sa_query(&resource.old))
            .await;
        let target = if resource.old.id == resource.new.id {
            None
        } else {
            Some(
                self.query_sa_relocation_identity(sa_query(&resource.new))
                    .await,
            )
        };
        let is_new = match (old, target) {
            (Ok(observed), None) if observed == identity(&resource.old) => false,
            (Ok(observed), None) if observed == identity(&resource.new) => true,
            (Ok(observed), Some(Err(XfrmError::NotFound)))
                if observed == identity(&resource.old) =>
            {
                false
            }
            (Err(XfrmError::NotFound), Some(Ok(observed)))
                if observed == identity(&resource.new) =>
            {
                true
            }
            _ => return Err(mismatch()),
        };
        let sa = if is_new { &resource.new } else { &resource.old };
        let mut policy = resource.policy.clone();
        policy.templates[0].id = sa.id;
        policy.templates[0].source_address = sa.source_address;
        let expected =
            validate_sa_policy_request(sa, &policy, policy.direction).map_err(|_| mismatch())?;
        // The policy is independently read below, and can currently be Block.
        // This call still proves full SA metadata, direction and transient keys.
        self.read_child_sa_binding(&expected, Some(sa), false)
            .await
            .map_err(|_| mismatch())?;
        Ok(is_new)
    }

    async fn policy(&self, resource: &PolicyMove) -> Result<PolicyParameters, XfrmError> {
        self.query_policy(policy_query(&resource.old)).await
    }

    async fn move_sa(&self, resource: &SaMove) -> Result<(), XfrmError> {
        self.relocate_sa(resource.request.clone()).await
    }

    async fn put_policy(&self, policy: &PolicyParameters) -> Result<(), XfrmError> {
        // UPDPOLICY replaces the exact selector/mark/interface identity under
        // the kernel policy lock, unlinks/kills the old policy and invalidates
        // cached routes. There is no remove/install plaintext-policy gap.
        self.rekey_policy(RekeyPolicyRequest {
            parameters: policy.clone(),
        })
        .await
    }
}

impl Program {
    /// Read every member before choosing any repair. Only a complete observed
    /// state reachable by a prefix of this exact program can be resumed.
    pub(crate) async fn prefix<B: RelocationIo + ?Sized>(
        &self,
        backend: &B,
    ) -> Result<usize, XfrmError> {
        let mut sas = Vec::with_capacity(self.sas.len());
        for resource in &self.sas {
            sas.push(backend.sa_is_new(resource).await?);
        }
        let mut policies = Vec::with_capacity(self.policies.len());
        for resource in &self.policies {
            let observed = backend.policy(resource).await?;
            let mut mask = 0u8;
            if observed == resource.old {
                mask |= 1;
            }
            if resource.block.as_ref() == Some(&observed) {
                mask |= 2;
            }
            if observed == resource.new {
                mask |= 4;
            }
            if mask == 0 {
                return Err(mismatch());
            }
            policies.push(mask);
        }
        let mut expected_sas = vec![false; self.sas.len()];
        let mut expected_policies = vec![0u8; self.policies.len()];
        let mut matched = None;
        for cut in 0..=self.steps.len() {
            if sas == expected_sas
                && policies
                    .iter()
                    .zip(&expected_policies)
                    .all(|(mask, phase)| mask & (1 << phase) != 0)
            {
                matched = Some(cut);
            }
            if let Some(step) = self.steps.get(cut) {
                match *step {
                    Step::Sa(index) => expected_sas[index] = true,
                    Step::Policy { index, phase } => expected_policies[index] = phase,
                }
            }
        }
        matched.ok_or_else(mismatch)
    }

    /// One error leaves the durable Issuing gate intact. Every successful
    /// individual mutation is followed by another complete readback, including
    /// cold/rekey members. No partial prefix publishes any installed authority.
    pub(crate) async fn finish<B, G>(
        &self,
        backend: &B,
        guard: G,
    ) -> Result<(), crate::ChildSaRelocationError>
    where
        B: RelocationIo + ?Sized,
        G: Fn() -> Result<(), crate::ChildSaRelocationError>,
    {
        self.finish_until(backend, guard, None).await
    }

    pub(crate) async fn finish_until<B, G>(
        &self,
        backend: &B,
        guard: G,
        detector_cut: Option<usize>,
    ) -> Result<(), crate::ChildSaRelocationError>
    where
        B: RelocationIo + ?Sized,
        G: Fn() -> Result<(), crate::ChildSaRelocationError>,
    {
        let mut previous = None;
        loop {
            let cut = self.prefix(backend).await?;
            if previous.is_some_and(|last| cut <= last) {
                return Err(mismatch().into());
            }
            guard()?;
            if detector_cut == Some(cut) {
                return Err(XfrmError::StateIndeterminate {
                    operation: "child_sa_roster_detector_cut",
                }
                .into());
            }
            let Some(step) = self.steps.get(cut) else {
                return Ok(());
            };
            match *step {
                Step::Sa(index) => backend.move_sa(&self.sas[index]).await?,
                Step::Policy { index, phase } => {
                    let resource = &self.policies[index];
                    let policy = if phase == 1 {
                        resource.block.as_ref().ok_or_else(mismatch)?
                    } else {
                        &resource.new
                    };
                    backend.put_policy(policy).await?;
                }
            }
            previous = Some(cut);
        }
    }
}
