//! Original, authenticated empty-candidate observations under RFC 019.

use serde::{Deserialize, Serialize};

use super::ledger::{authenticate, verify, HandleBody};
use super::{
    AuditAuthorityError, AuditCaller, AuditOperationBinding, AuditOperationHandle,
    AuditPrivacyProjection, NetconfSessionOwner, ProjectedAuditEvent,
};
use crate::{
    AuditKey, ConfigConsensusIdentity, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTransportCode,
};

const GUARD_DOMAIN: &[u8] = b"openpacketcore/management-audit/netconf-empty-commit/v1\0";
const MAX_EMPTY_COMMIT_BYTES: usize = 32 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyCommitGuard {
    pub(crate) format: u16,
    #[serde(with = "super::target_identity")]
    pub(crate) authority: ConfigConsensusIdentity,
    pub(crate) profile_incarnation: [u8; 16],
    pub(crate) device_incarnation: [u8; 16],
    #[serde(with = "super::target_caller")]
    pub(crate) caller: AuditCaller,
    pub(crate) session: [u8; 16],
    pub(crate) candidate_generation: u64,
    pub(crate) state_digest: [u8; 32],
    pub(crate) running_base: u64,
}

/// One quorum-current, independently checkpointed empty candidate/lifecycle read.
/// Its original worker/session owns preparation; it grants no admission by itself.
#[derive(Clone)]
pub struct NetconfEmptyCommitRead {
    pub(crate) session: NetconfSessionOwner,
    pub(crate) guard: EmptyCommitGuard,
}

impl NetconfEmptyCommitRead {
    /// Exact running expectation, including the initial empty revision zero.
    pub const fn running_base(&self) -> u64 {
        self.guard.running_base
    }

    pub(crate) fn verify_session(
        &self,
        session: &NetconfSessionOwner,
    ) -> Result<(), AuditAuthorityError> {
        session.require_active()?;
        if !self.session.same_session(session)
            || self.guard.authority != session.device.authority
            || self.guard.profile_incarnation != session.device.profile_incarnation
            || self.guard.device_incarnation != session.device.device_incarnation
            || self.guard.caller != session.caller
            || self.guard.session != session.incarnation()
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        key: &AuditKey,
        privacy: &dyn AuditPrivacyProjection,
        session: &NetconfSessionOwner,
        event: ProjectedAuditEvent,
        window: std::ops::Range<i64>,
        nonce: [u8; 16],
    ) -> Result<PreparedNetconfEmptyCommit, AuditAuthorityError> {
        self.verify_session(session)?;
        let canonical =
            serde_json::to_vec(&self.guard).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let binding =
            AuditOperationBinding::project(privacy, &event, self.running_base(), &canonical)?;
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.guard.authority,
                binding,
                event,
                issued_at: window.start,
                expires_at: window.end,
                nonce,
                key_epoch: key.epoch(),
                mutation: None,
            },
            key,
        )?;
        let guard_mac = authenticate(key, GUARD_DOMAIN, &(&handle, &self.guard))?;
        let prepared = PreparedNetconfEmptyCommit {
            handle,
            guard: self.guard.clone(),
            guard_mac,
        };
        prepared.verify(key, self.guard.authority, session.caller)?;
        Ok(prepared)
    }
}

/// A bounded observation of one exact empty state, never a configuration effect.
/// Persist the original before admission and reuse it after acknowledgement loss.
/// Decoding does not authenticate its guard or grant signing authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedNetconfEmptyCommit {
    #[serde(deserialize_with = "super::ledger::deserialize_target_handle")]
    pub(crate) handle: AuditOperationHandle,
    pub(crate) guard: EmptyCommitGuard,
    pub(crate) guard_mac: [u8; 32],
}

impl PreparedNetconfEmptyCommit {
    /// Original opaque observation handle; it cannot authorize a mutation.
    pub fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }

    /// Encode for protected recovery storage, never diagnostics.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        let bytes = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.len() > MAX_EMPTY_COMMIT_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(bytes)
    }

    /// Decode bounded untrusted recovery bytes. Admission authenticates all fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        if bytes.len() > MAX_EMPTY_COMMIT_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)
    }

    pub(crate) fn verify(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        self.handle.verify(key, identity, caller)?;
        let event = &self.handle.body.event;
        if self.guard.format != 1
            || self.guard.authority != identity
            || self.guard.caller != caller
            || self.guard.profile_incarnation == [0; 16]
            || self.guard.device_incarnation == [0; 16]
            || self.guard.session == [0; 16]
            || self.guard.state_digest == [0; 32]
            || self.guard.running_base != self.handle.body.binding.base_version
            || self.guard.running_base > i64::MAX as u64
            || event.caller != caller
            || event.request != self.handle.body.binding.request
            || !matches!(
                event.transport,
                ManagementAuditTransportCode::NetconfSsh | ManagementAuditTransportCode::NetconfTls
            )
            || event.operation != ManagementAuditOperationCode::Commit
            || event.outcome != ManagementAuditOutcomeCode::Success
            || event.transaction.is_some()
            || self.handle.body.mutation.is_some()
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(
            key,
            GUARD_DOMAIN,
            &(&self.handle, &self.guard),
            &self.guard_mac,
        )
    }
}

impl std::fmt::Debug for NetconfEmptyCommitRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NetconfEmptyCommitRead(<redacted>)")
    }
}

impl std::fmt::Debug for PreparedNetconfEmptyCommit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedNetconfEmptyCommit(<redacted>)")
    }
}
