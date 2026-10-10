//! Narrow transport admission and retained-outcome adapters; no wire capability.
use super::*;
use async_trait::async_trait;
use std::sync::Arc;

/// Configured trusted transport verifier, installed by the host. Its implementation
/// must perform the real authenticated request, validate its exact ID and digest,
/// scope, role, boot key and current committed result on the same live connection.
/// A decoded stamp, read response or serialized verification token is insufficient.
#[async_trait]
pub trait ScopeAuthorityResponseVerifier: Send + Sync {
    /// Return a stamp only after this boot's admission/succession result is verified
    /// as committed and still current. Controller/read results must be refused.
    async fn verify_own_current(
        &self,
        request: &ScopeAuthorityRequest,
        execution: &ScopeExecution,
    ) -> Result<ScopeAuthorityStamp, ScopeAuthorityError>;
}
/// A remote authority boundary bound to one local boot and a trusted verifier.
pub struct ScopeAuthorityRemote {
    scope: ScopeId,
    execution: ScopeExecution,
    verifier: Arc<dyn ScopeAuthorityResponseVerifier>,
}
impl ScopeAuthorityRemote {
    /// Install the exact local execution and the authenticated transport verifier.
    pub fn new(
        scope: ScopeId,
        execution: ScopeExecution,
        verifier: Arc<dyn ScopeAuthorityResponseVerifier>,
    ) -> Result<Self, ScopeAuthorityError> {
        execution.validate()?;
        if scope.slot == [0; 32] {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(Self {
            scope,
            execution,
            verifier,
        })
    }
    /// Verify the exact own admission/succession result before producing authority.
    pub async fn admit(
        &self,
        request: &ScopeAuthorityRequest,
    ) -> Result<CommittedScopeAuthority, ScopeAuthorityError> {
        request.validate()?;
        if matches!(request.operation, ScopeAuthorityOperation::Close { .. }) {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        if request.scope != self.scope || request.operation.execution() != &self.execution {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        let expected_revision = request
            .expected_revision
            .checked_add(1)
            .filter(|revision| *revision <= COUNTER_MAX)
            .ok_or(ScopeAuthorityError::InvalidRequest)?;
        let closed_predecessor = match &request.operation {
            ScopeAuthorityOperation::AdmitInitial { .. } => {
                if request.expected_revision != 0 {
                    return Err(ScopeAuthorityError::InvalidRequest);
                }
                None
            }
            ScopeAuthorityOperation::SucceedClosed {
                predecessor,
                execution,
                evidence,
            } => {
                if predecessor.revision != request.expected_revision
                    || execution.admission_generation <= predecessor.execution.admission_generation
                    || execution.process == predecessor.execution.process
                    || execution.boot_key == predecessor.execution.boot_key
                    || !matches!(
                        evidence.kind,
                        ScopeClosureKind::FinalTermination | ScopeClosureKind::CommittedClose
                    )
                {
                    return Err(ScopeAuthorityError::InvalidRequest);
                }
                Some(predecessor.clone())
            }
            ScopeAuthorityOperation::Close { .. } => {
                return Err(ScopeAuthorityError::InvalidRequest)
            }
        };
        let stamp = self
            .verifier
            .verify_own_current(request, &self.execution)
            .await?;
        stamp
            .validate()
            .map_err(|_| ScopeAuthorityError::StaleAuthority)?;
        if stamp.scope() != &self.scope
            || stamp.execution != self.execution
            || stamp.revision != expected_revision
            || closed_predecessor
                .as_ref()
                .is_some_and(|previous| previous.namespace != stamp.namespace)
            || (closed_predecessor.is_none() && stamp.incarnation().get() != 1)
        {
            return Err(ScopeAuthorityError::StaleAuthority);
        }
        Ok(CommittedScopeAuthority {
            stamp,
            closed_predecessor,
        })
    }
}
/// What one full-round authority read proves about an exact retained request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeAuthorityOutcome {
    /// The currently retained receipt exactly matches both request ID and digest.
    Committed(ScopeAuthorityView),
    /// This receipt is not retained. Its old effect is unknown, never NotApplied.
    ReceiptUnavailable(ScopeAuthorityView),
}
impl ScopeAuthorityStore {
    /// Read an exact authority outcome after scope authorization, using the native
    /// full-round barrier. This path never proposes or constructs a capability.
    pub async fn outcome(
        &self,
        authenticated: &SessionConsumerIdentity,
        request_id: [u8; 16],
        digest: [u8; 32],
    ) -> Result<ScopeAuthorityOutcome, ScopeAuthorityError> {
        if request_id == [0; 16] || digest == [0; 32] {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        tokio::time::timeout(crate::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(
                    authenticated,
                    &self.scope,
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            let current = self.backend.current(&self.scope).await?;
            self.admission
                .authorize(
                    authenticated,
                    &self.scope,
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            if current.view.scope != self.scope {
                return Err(ScopeAuthorityError::FormatMismatch);
            }
            if current.last_request_id != request_id {
                return Ok(ScopeAuthorityOutcome::ReceiptUnavailable(current.view));
            }
            if current.last_digest != digest {
                return Err(ScopeAuthorityError::IdempotencyConflict);
            }
            self.admission
                .authorize(
                    authenticated,
                    &self.scope,
                    current
                        .view
                        .stamp
                        .as_ref()
                        .map(ScopeAuthorityStamp::execution),
                    ScopeAuthorityAction::Recover,
                    Some(digest),
                )
                .await?;
            Ok(ScopeAuthorityOutcome::Committed(current.view))
        })
        .await
        .map_err(|_| ScopeAuthorityError::Unavailable)?
    }
}
impl ScopeAuthorityRequest {
    /// Canonical unchanged Postcard bytes bounded by the authority protocol limit.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeAuthorityError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
        if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(bytes)
    }
    /// Decode and reject trailing bytes, noncanonical integers and oversized input.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeAuthorityError> {
        if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        let (value, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
        if !trailing.is_empty() || value.encode_canonical()? != bytes {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(value)
    }
}
