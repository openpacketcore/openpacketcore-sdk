//! Privacy and operation-binding primitives for the replicated management ledger.
//!
//! These types do not turn a local audit acknowledgement into a fleet receipt.
//! Only the configuration consensus adapter may issue an applied receipt.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::management_audit::{
    ManagementAuditEventRecord, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTransportCode,
};

pub use crate::consensus::{PreparedAuditedMutation, PreparedTargetMutation};
/// Authenticated retained epochs, portable exports and external checkpoints.
pub mod continuity;
pub(crate) mod ledger;
pub(crate) mod receipt;
mod targets;
pub use ledger::{
    AuditAdmission, AuditLedgerLimits, AuditOperationHandle, AuditOperationReceipt,
    AuditOperationState,
};
pub(crate) use targets::{caller as target_caller, identity as target_identity};
pub use targets::{
    CandidateGeneration, NetconfAppliedOutcome, NetconfIncarnation, NetconfPendingConfirmation,
    NetconfTargetResult, StartupRevision,
};

/// Largest aggregate private tuple accepted before projection.
pub const AUDIT_OPERATION_MAX_BYTES: usize = 256 * 1024;

/// Value-free progress from one bounded SDK recovery pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditRecoveryProgress {
    /// Retained obligations inspected by this pass.
    pub inspected: usize,
    /// Terminal records proven durable after recovery.
    pub completed: usize,
    /// Unexpired intents still awaiting a configuration decision.
    pub pending: usize,
    /// Operations requiring another authoritative read after uncertainty.
    pub unknown: usize,
}

/// Closed failure classes; no private input or backend detail is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuditAuthorityError {
    /// An input exceeds its bound or is not representable.
    #[error("invalid audit authority input")]
    InvalidInput,
    /// The supplied key is absent, empty, or unsuitable for its purpose.
    #[error("audit authority key unavailable")]
    KeyUnavailable,
    /// Caller, operation, fleet, predecessor, or authentication did not match.
    #[error("audit authority binding mismatch")]
    BindingMismatch,
    /// A fixed admission or cursor deadline has elapsed.
    #[error("audit authority handle expired")]
    Expired,
    /// The requested history was explicitly and safely retained away.
    #[error("audit authority history pruned")]
    Pruned,
    /// Required authoritative readback cannot be established.
    #[error("audit authority unavailable")]
    Unavailable,
    /// Safe pruning cannot free enough reserved capacity for this operation.
    #[error("audit authority capacity exhausted")]
    Full,
    /// The local history or external checkpoint moved behind an authenticated bound.
    #[error("audit authority rollback detected")]
    RollbackDetected,
    /// A checkpointed mutation has no retained authoritative outcome after
    /// reopen. Expiry is not proof that its possibly lost effect did not commit.
    #[error("audit authority recovery required")]
    RecoveryRequired,
}

/// A projected identifier. It is not a metric label or diagnostic identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuditToken([u8; 32]);

impl AuditToken {
    /// Import the output of an approved keyed projection provider.
    /// This token is correlation data, never an authorization capability.
    pub fn from_keyed_projection(bytes: [u8; 32]) -> Result<Self, AuditAuthorityError> {
        if bytes == [0; 32] {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for AuditToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditToken(<redacted>)")
    }
}

/// Closed purposes prevent cross-field substitution in a projection provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditPrivacyPurpose {
    /// Binding for the admitted projection material.
    KeyIdentity,
    /// Authenticated tenant scope.
    Tenant,
    /// Principal within the authenticated tenant.
    Principal,
    /// Request identity within its caller scope.
    Request,
    /// Transaction identity within its caller scope.
    Transaction,
    /// Canonical operation content and base revision.
    Operation,
    /// Ordered schema-node path description.
    SchemaPaths,
    /// Stable outcome reason.
    Reason,
}

impl AuditPrivacyPurpose {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::KeyIdentity => b"key-identity",
            Self::Tenant => b"tenant",
            Self::Principal => b"principal",
            Self::Request => b"request",
            Self::Transaction => b"transaction",
            Self::Operation => b"operation",
            Self::SchemaPaths => b"schema-paths",
            Self::Reason => b"reason",
        }
    }
}

/// SDK privacy projection boundary, invoked before any queue, log, or storage.
///
/// Implementations must use a purpose-separated keyed transformation, never
/// truncation or an unkeyed hash. The same admitted key epoch must be available
/// on every voter serving this ledger. Changing it is a separately authenticated
/// transition, not permission to reinterpret existing tokens.
pub trait AuditPrivacyProjection: Send + Sync {
    /// Project a length-delimited tuple under one closed purpose.
    fn project(
        &self,
        purpose: AuditPrivacyPurpose,
        fields: &[&[u8]],
    ) -> Result<AuditToken, AuditAuthorityError>;
}

/// Default zeroizing HMAC-SHA-256 projection key, separate from audit signing.
pub struct AuditPrivacyKey(Zeroizing<[u8; 32]>);

impl AuditPrivacyKey {
    /// Admit explicit nonzero secret material. No implicit or development key exists.
    pub fn new(material: [u8; 32]) -> Result<Self, AuditAuthorityError> {
        let material = Zeroizing::new(material);
        if material.iter().all(|byte| *byte == 0) {
            return Err(AuditAuthorityError::KeyUnavailable);
        }
        Ok(Self(material))
    }
}

impl fmt::Debug for AuditPrivacyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditPrivacyKey(<redacted>)")
    }
}

impl AuditPrivacyProjection for AuditPrivacyKey {
    fn project(
        &self,
        purpose: AuditPrivacyPurpose,
        fields: &[&[u8]],
    ) -> Result<AuditToken, AuditAuthorityError> {
        if fields.len() > 256 {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| AuditAuthorityError::KeyUnavailable)?;
        mac.update(b"openpacketcore/management-audit/privacy/v1\0");
        mac.update(&(purpose.domain().len() as u64).to_be_bytes());
        mac.update(purpose.domain());
        mac.update(&(fields.len() as u64).to_be_bytes());
        let mut total = 0usize;
        for field in fields {
            total = total
                .checked_add(field.len())
                .filter(|total| *total <= AUDIT_OPERATION_MAX_BYTES)
                .ok_or(AuditAuthorityError::InvalidInput)?;
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        Ok(AuditToken(mac.finalize().into_bytes().into()))
    }
}

/// Fixed-width caller scope derived exclusively from trusted authentication input.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCaller {
    tenant: AuditToken,
    principal: AuditToken,
}

impl AuditCaller {
    /// Bind a tenant and principal through the admitted privacy provider.
    pub fn project(
        privacy: &dyn AuditPrivacyProjection,
        tenant: &str,
        principal: &str,
    ) -> Result<Self, AuditAuthorityError> {
        if tenant.is_empty()
            || principal.is_empty()
            || tenant.len() > crate::MANAGEMENT_AUDIT_MAX_TENANT_BYTES
            || principal.len() > crate::MANAGEMENT_AUDIT_MAX_PRINCIPAL_BYTES
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(Self {
            tenant: privacy.project(AuditPrivacyPurpose::Tenant, &[tenant.as_bytes()])?,
            principal: privacy.project(
                AuditPrivacyPurpose::Principal,
                &[tenant.as_bytes(), principal.as_bytes()],
            )?,
        })
    }
}

impl fmt::Debug for AuditCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditCaller(<redacted>)")
    }
}

/// Persistable event containing no raw request, transaction, caller, or path.
///
/// Stable enum codes and the source timestamp are retained. They do not supply
/// consensus ordering; that ordering comes from the applied ledger sequence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedAuditEvent {
    pub(crate) projection: AuditToken,
    pub(crate) caller: AuditCaller,
    pub(crate) request: AuditToken,
    pub(crate) transaction: Option<AuditToken>,
    pub(crate) paths: AuditToken,
    pub(crate) reason: Option<AuditToken>,
    pub(crate) transport: ManagementAuditTransportCode,
    pub(crate) operation: ManagementAuditOperationCode,
    pub(crate) outcome: ManagementAuditOutcomeCode,
    pub(crate) utc_seconds: i64,
    pub(crate) nanosecond: u32,
}

impl ProjectedAuditEvent {
    /// Project the already bounded, validated source event before it is retained.
    pub fn project(
        privacy: &dyn AuditPrivacyProjection,
        event: &ManagementAuditEventRecord,
    ) -> Result<Self, AuditAuthorityError> {
        let caller = AuditCaller::project(privacy, event.tenant(), event.principal())?;
        let scope = [event.tenant().as_bytes(), event.principal().as_bytes()];
        let paths: Vec<&[u8]> = event
            .schema_paths()
            .iter()
            .map(|path| path.as_bytes())
            .collect();
        Ok(Self {
            projection: privacy.project(AuditPrivacyPurpose::KeyIdentity, &[])?,
            caller,
            request: privacy.project(
                AuditPrivacyPurpose::Request,
                &[scope[0], scope[1], event.request_id()],
            )?,
            transaction: event
                .tx_id()
                .map(|tx| {
                    privacy.project(
                        AuditPrivacyPurpose::Transaction,
                        &[scope[0], scope[1], tx.as_bytes()],
                    )
                })
                .transpose()?,
            paths: privacy.project(AuditPrivacyPurpose::SchemaPaths, &paths)?,
            reason: event
                .reason()
                .map(|reason| privacy.project(AuditPrivacyPurpose::Reason, &[reason.as_bytes()]))
                .transpose()?,
            transport: event.transport(),
            operation: event.operation(),
            outcome: event.outcome(),
            utc_seconds: event.occurred_at().utc_seconds(),
            nanosecond: event.occurred_at().nanosecond(),
        })
    }
}

impl fmt::Debug for ProjectedAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProjectedAuditEvent(<redacted>)")
    }
}

/// Immutable authorization binding for one exact operation and base revision.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOperationBinding {
    pub(crate) caller: AuditCaller,
    pub(crate) request: AuditToken,
    pub(crate) operation: AuditToken,
    pub(crate) base_version: u64,
}

impl AuditOperationBinding {
    /// Bind a canonical SDK operation representation, without retaining it.
    ///
    /// The representation must include the operation kind, mode, canonical
    /// candidate content/digest, and control target. Adapters own that encoding;
    /// schema paths alone cannot distinguish writes of different values.
    pub fn project(
        privacy: &dyn AuditPrivacyProjection,
        event: &ProjectedAuditEvent,
        base_version: u64,
        canonical_operation: &[u8],
    ) -> Result<Self, AuditAuthorityError> {
        if canonical_operation.is_empty() || base_version > i64::MAX as u64 {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(Self {
            caller: event.caller,
            request: event.request,
            operation: privacy.project(
                AuditPrivacyPurpose::Operation,
                &[
                    &event.caller.tenant.0,
                    &event.caller.principal.0,
                    &event.request.0,
                    &base_version.to_be_bytes(),
                    canonical_operation,
                ],
            )?,
            base_version,
        })
    }
}

impl fmt::Debug for AuditOperationBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditOperationBinding(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
