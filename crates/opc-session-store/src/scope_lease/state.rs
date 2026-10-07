//! Deterministic bounded scope-record transitions, checked by native consensus apply.

use sha2::{Digest, Sha256};

use super::*;

fn next(value: u64) -> Result<u64, ScopeLeaseError> {
    value
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
        .ok_or(ScopeLeaseError::InvalidRequest)
}

fn deadline(origin: Timestamp, duration: Duration) -> Result<Timestamp, ScopeLeaseError> {
    crate::checked_session_deadline(origin, duration).map_err(|_| ScopeLeaseError::ClockUncertain)
}

impl ScopeLeaseRequest {
    pub(crate) fn validate(&self) -> Result<(), ScopeLeaseError> {
        if self.request_id == [0; 16]
            || self.scope.slot == [0; 32]
            || self.expected_revision > i64::MAX as u64
        {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        self.operation.execution().validate()?;
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], ScopeLeaseError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| ScopeLeaseError::InvalidRequest)?;
        if bytes.len() > MAX_SCOPE_LEASE_RECORD_BYTES {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope-lease/request/v2\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

impl ScopePermit {
    fn issue(
        scope: &ScopeLeaseId,
        execution: &ScopeExecution,
        selection: u64,
        grant_epoch: u64,
        now: ScopeClockBounds,
    ) -> Result<Self, ScopeLeaseError> {
        let issued_at = now.latest;
        let renew_by = deadline(issued_at, SCOPE_RENEWAL_INTERVAL)?;
        let stop_at = deadline(renew_by, SCOPE_FORWARDING_GRACE)?;
        let excluded_until = deadline(stop_at, SCOPE_CLOCK_GUARD)?;
        Ok(Self {
            scope: scope.clone(),
            execution: execution.clone(),
            selection,
            grant_epoch,
            issued_at,
            renew_by,
            stop_at,
            excluded_until,
        })
    }

    fn validate(&self) -> Result<(), ScopeLeaseError> {
        self.execution.validate()?;
        if self.scope.slot == [0; 32]
            || self.selection == 0
            || self.selection > i64::MAX as u64
            || self.grant_epoch == 0
            || self.grant_epoch > self.selection
            || self.selection != self.execution.admission_generation
            || self.renew_by != deadline(self.issued_at, SCOPE_RENEWAL_INTERVAL)?
            || self.stop_at != deadline(self.renew_by, SCOPE_FORWARDING_GRACE)?
            || self.excluded_until != deadline(self.stop_at, SCOPE_CLOCK_GUARD)?
        {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(())
    }
}

impl ScopeState {
    pub(crate) fn empty(scope: ScopeLeaseId) -> Self {
        Self {
            view: ScopeLeaseView {
                scope,
                revision: 0,
                selection: 0,
                selected: None,
                grant_floor: 0,
                granted_selection: 0,
                permit: None,
            },
            last_request_id: [0; 16],
            last_digest: [0; 32],
            last_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    /// Replay is deliberately independent of current time. It returns old
    /// absolute deadlines, never a fresh grant based on receipt or retry time.
    pub(crate) fn replay(&self, request: &ScopeLeaseRequest) -> Result<bool, ScopeLeaseError> {
        if request.scope != self.view.scope {
            return Err(ScopeLeaseError::Unauthorized);
        }
        let digest = request.digest()?;
        if request.request_id == self.last_request_id {
            if digest != self.last_digest {
                return Err(ScopeLeaseError::IdempotencyConflict);
            }
            return Ok(true);
        }
        if request.expected_revision != self.view.revision {
            return Err(ScopeLeaseError::Conflict);
        }
        Ok(false)
    }

    pub(crate) fn transition(
        &self,
        request: &ScopeLeaseRequest,
        now: ScopeClockBounds,
    ) -> Result<Self, ScopeLeaseError> {
        if self.replay(request)? {
            return Ok(self.clone());
        }
        if now.latest < self.last_time {
            return Err(ScopeLeaseError::ClockUncertain);
        }
        let mut successor = self.clone();
        let view = &mut successor.view;
        match &request.operation {
            ScopeLeaseOperation::Select { execution } => {
                if execution.admission_generation <= view.selection {
                    return Err(ScopeLeaseError::Superseded);
                }
                if view
                    .permit
                    .as_ref()
                    .is_some_and(|permit| now.earliest < permit.stop_at)
                {
                    return Err(ScopeLeaseError::Held);
                }
                view.selection = execution.admission_generation;
                view.selected = Some(execution.clone());
            }
            ScopeLeaseOperation::Acquire {
                execution,
                selection,
            } => {
                if *selection != view.selection
                    || view.selected.as_ref() != Some(execution)
                    || *selection <= view.granted_selection
                {
                    return Err(ScopeLeaseError::Superseded);
                }
                if view
                    .permit
                    .as_ref()
                    .is_some_and(|permit| now.earliest < permit.excluded_until)
                {
                    return Err(ScopeLeaseError::Held);
                }
                view.grant_floor = next(view.grant_floor)?;
                view.granted_selection = *selection;
                view.permit = Some(ScopePermit::issue(
                    &view.scope,
                    execution,
                    *selection,
                    view.grant_floor,
                    now,
                )?);
            }
            ScopeLeaseOperation::Renew { permit }
            | ScopeLeaseOperation::ResumeSameExecution { permit } => {
                if view.permit.as_ref() != Some(permit) {
                    return Err(ScopeLeaseError::StalePermit);
                }
                if view.selection != permit.selection
                    || view.selected.as_ref() != Some(&permit.execution)
                {
                    return Err(ScopeLeaseError::Superseded);
                }
                if matches!(&request.operation, ScopeLeaseOperation::Renew { .. }) {
                    if now.latest >= permit.stop_at {
                        return Err(ScopeLeaseError::Expired);
                    }
                } else if now.earliest < permit.stop_at {
                    return Err(ScopeLeaseError::Held);
                }
                view.permit = Some(ScopePermit::issue(
                    &view.scope,
                    &permit.execution,
                    permit.selection,
                    permit.grant_epoch,
                    now,
                )?);
            }
            ScopeLeaseOperation::Release { closed } => {
                if view.permit.as_ref() != Some(&closed.permit) {
                    return Err(ScopeLeaseError::StalePermit);
                }
                view.permit = None;
            }
        }
        view.revision = next(view.revision)?;
        successor.last_request_id = request.request_id;
        successor.last_digest = request.digest()?;
        successor.last_time = now.latest;
        successor.validate()?;
        Ok(successor)
    }

    fn validate(&self) -> Result<(), ScopeLeaseError> {
        let view = &self.view;
        if view.scope.slot == [0; 32]
            || view.revision == 0
            || view.revision > i64::MAX as u64
            || view.selection == 0
            || view.selection > i64::MAX as u64
            || view.grant_floor > view.granted_selection
            || view.granted_selection > view.selection
            || (view.grant_floor == 0) != (view.granted_selection == 0)
            || self.last_request_id == [0; 16]
        {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        view.selected
            .as_ref()
            .ok_or(ScopeLeaseError::FormatMismatch)?
            .validate()
            .map_err(|_| ScopeLeaseError::FormatMismatch)?;
        if view
            .selected
            .as_ref()
            .map(ScopeExecution::admission_generation)
            != Some(view.selection)
        {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        if let Some(permit) = &view.permit {
            permit
                .validate()
                .map_err(|_| ScopeLeaseError::FormatMismatch)?;
            if permit.scope != view.scope
                || permit.grant_epoch != view.grant_floor
                || permit.selection != view.granted_selection
                || permit.issued_at > self.last_time
                || (permit.selection == view.selection
                    && view.selected.as_ref() != Some(&permit.execution))
            {
                return Err(ScopeLeaseError::FormatMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ScopeLeaseError> {
        self.validate()?;
        let mut bytes = Vec::from(RECORD_MAGIC.as_slice());
        bytes.extend(postcard::to_allocvec(self).map_err(|_| ScopeLeaseError::FormatMismatch)?);
        if bytes.len() > MAX_SCOPE_LEASE_RECORD_BYTES {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8], scope: &ScopeLeaseId) -> Result<Self, ScopeLeaseError> {
        let value = Self::decode_any(bytes)?;
        if &value.view.scope != scope {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        Ok(value)
    }

    pub(crate) fn decode_any(bytes: &[u8]) -> Result<Self, ScopeLeaseError> {
        if bytes.len() > MAX_SCOPE_LEASE_RECORD_BYTES || !bytes.starts_with(RECORD_MAGIC) {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        let (value, trailing): (Self, &[u8]) =
            postcard::take_from_bytes(&bytes[RECORD_MAGIC.len()..])
                .map_err(|_| ScopeLeaseError::FormatMismatch)?;
        if !trailing.is_empty() {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        value.validate()?;
        Ok(value)
    }
}
