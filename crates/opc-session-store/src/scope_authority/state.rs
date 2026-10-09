//! Pure, untimed authority transitions shared by every replicated apply path.

use super::*;
use sha2::{Digest, Sha256};

fn next(value: u64) -> Result<u64, ScopeAuthorityError> {
    value
        .checked_add(1)
        .filter(|value| *value <= COUNTER_MAX)
        .ok_or(ScopeAuthorityError::InvalidRequest)
}

impl ScopeAuthorityRequest {
    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        if self.request_id == [0; 16]
            || self.scope.slot == [0; 32]
            || self.expected_revision > COUNTER_MAX
        {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        self.operation.execution().validate()?;
        if let Some((predecessor, evidence)) = self.operation.closure() {
            predecessor.validate()?;
            if predecessor.scope() != &self.scope || evidence.digest == [0; 32] {
                return Err(ScopeAuthorityError::InvalidRequest);
            }
        }
        Ok(())
    }

    /// Canonical immutable identity for transport binding and exact retries.
    /// Current voter/configuration admission is deliberately outside this hash.
    pub fn digest(&self) -> Result<[u8; 32], ScopeAuthorityError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
        if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-authority/request/v4\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

impl ScopeState {
    pub(crate) fn empty(scope: ScopeId) -> Self {
        Self {
            view: ScopeAuthorityView {
                scope,
                revision: 0,
                retired_through: 0,
                admission_generation_floor: 0,
                stamp: None,
                active: false,
                closed_digest: None,
            },
            last_request_id: [0; 16],
            last_digest: [0; 32],
        }
    }

    pub(crate) fn replay(
        &self,
        request: &ScopeAuthorityRequest,
    ) -> Result<bool, ScopeAuthorityError> {
        if request.scope != self.view.scope {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        let digest = request.digest()?;
        if request.request_id == self.last_request_id {
            return if digest == self.last_digest {
                Ok(true)
            } else {
                Err(ScopeAuthorityError::IdempotencyConflict)
            };
        }
        if request.expected_revision != self.view.revision {
            return Err(ScopeAuthorityError::Conflict);
        }
        Ok(false)
    }

    fn current_stamp(&self, stamp: &ScopeAuthorityStamp) -> Result<(), ScopeAuthorityError> {
        stamp.validate()?;
        if stamp.scope() != &self.view.scope {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if stamp.incarnation().get() <= self.view.retired_through {
            return Err(ScopeAuthorityError::Retired);
        }
        if self.view.stamp.as_ref() != Some(stamp)
            || stamp.execution.admission_generation != self.view.admission_generation_floor
        {
            return Err(ScopeAuthorityError::StaleAuthority);
        }
        Ok(())
    }

    pub(crate) fn check_stamp(
        &self,
        stamp: &ScopeAuthorityStamp,
    ) -> Result<(), ScopeAuthorityError> {
        self.current_stamp(stamp)?;
        if !self.view.active {
            return Err(ScopeAuthorityError::StaleAuthority);
        }
        Ok(())
    }

    /// Admission/closure verification happens before constructing the command.
    /// Apply independently compares every durable predecessor fact here.
    pub(crate) fn transition(
        &self,
        request: &ScopeAuthorityRequest,
    ) -> Result<Self, ScopeAuthorityError> {
        if self.replay(request)? {
            return Ok(self.clone());
        }
        let revision = next(self.view.revision)?;
        let (namespace, execution, active) = match &request.operation {
            ScopeAuthorityOperation::AdmitInitial { execution } => {
                if self.view.revision != 0
                    || self.view.stamp.is_some()
                    || self.view.admission_generation_floor != 0
                    || self.view.retired_through != 0
                {
                    return Err(ScopeAuthorityError::Conflict);
                }
                (
                    ScopeNamespace::new(self.view.scope.clone(), ScopeIncarnation::new(1)?)?,
                    execution.clone(),
                    true,
                )
            }
            ScopeAuthorityOperation::SucceedClosed {
                predecessor,
                execution,
                evidence,
            } => {
                self.current_stamp(predecessor)?;
                match evidence.kind {
                    ScopeClosureKind::FinalTermination => {}
                    ScopeClosureKind::CommittedClose
                        if !self.view.active
                            && self.view.closed_digest == Some(evidence.digest) => {}
                    _ => return Err(ScopeAuthorityError::ClosureRequired),
                }
                if execution.admission_generation <= self.view.admission_generation_floor
                    || execution.process == predecessor.execution.process
                    || execution.boot_key == predecessor.execution.boot_key
                {
                    return Err(ScopeAuthorityError::Superseded);
                }
                (predecessor.namespace.clone(), execution.clone(), true)
            }
            ScopeAuthorityOperation::Close { current, evidence } => {
                self.check_stamp(current)?;
                if evidence.kind != ScopeClosureKind::LocalQuiescence {
                    return Err(ScopeAuthorityError::ClosureRequired);
                }
                (current.namespace.clone(), current.execution.clone(), false)
            }
        };
        let digest = request.digest()?;
        let next = Self {
            view: ScopeAuthorityView {
                scope: self.view.scope.clone(),
                revision,
                retired_through: self.view.retired_through,
                admission_generation_floor: execution.admission_generation,
                stamp: Some(ScopeAuthorityStamp {
                    namespace,
                    revision,
                    execution,
                }),
                active,
                closed_digest: (!active).then_some(digest),
            },
            last_request_id: request.request_id,
            last_digest: digest,
        };
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        let view = &self.view;
        let stamp = view
            .stamp
            .as_ref()
            .ok_or(ScopeAuthorityError::FormatMismatch)?;
        stamp
            .validate()
            .map_err(|_| ScopeAuthorityError::FormatMismatch)?;
        if view.scope.slot == [0; 32]
            || !(1..=COUNTER_MAX).contains(&view.revision)
            || view.retired_through >= stamp.incarnation().get()
            || view.admission_generation_floor != stamp.execution.admission_generation
            || stamp.scope() != &view.scope
            || stamp.revision != view.revision
            || self.last_request_id == [0; 16]
            || self.last_digest == [0; 32]
            || (view.active && view.closed_digest.is_some())
            || (!view.active && view.closed_digest != Some(self.last_digest))
        {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ScopeAuthorityError> {
        self.validate()?;
        let mut bytes = RECORD_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(self).map_err(|_| ScopeAuthorityError::FormatMismatch)?);
        if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(bytes)
    }
    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], scope: &ScopeId) -> Result<Self, ScopeAuthorityError> {
        let value = Self::decode_any(bytes)?;
        if &value.view.scope != scope {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        Ok(value)
    }
    pub(crate) fn decode_any(bytes: &[u8]) -> Result<Self, ScopeAuthorityError> {
        if bytes.starts_with(b"OPSL") {
            return Err(ScopeAuthorityError::FreshInstallationRequired);
        }
        if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES || !bytes.starts_with(RECORD_MAGIC) {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        let (value, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(&bytes[RECORD_MAGIC.len()..])
                .map_err(|_| ScopeAuthorityError::FormatMismatch)?;
        if !trailing.is_empty() {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        value.validate()?;
        Ok(value)
    }
}
