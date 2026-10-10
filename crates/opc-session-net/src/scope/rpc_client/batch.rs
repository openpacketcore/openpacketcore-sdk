//! Authenticated access for the shared lane coordinator.
use super::*;
use opc_session_store::{scope_batch::*, scope_scheduler::ScopeWorkClass};

impl ScopeClient {
    /// Open this boot's shared batch coordinator under one read reservation.
    /// Factories for the same admitted execution share lanes, exact pending
    /// requests and unacknowledged completions, including after reconnection.
    /// Service its completion stream and acknowledge each reconciled result.
    pub async fn batches(
        &self,
        authority: &CommittedScopeAuthority,
        class: ScopeWorkClass,
        attempt: Duration,
    ) -> Result<ScopeBatchCoordinator, ScopeBatchError> {
        authority.check_execution(&self.0.execution)?;
        if authority.stamp().scope() != &self.0.config.scope {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        data_class(class)?;
        if attempt.is_zero() {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let _opening = self.batch_read_permit(class).await?;
        let port = Arc::new(BatchPort {
            client: self.clone(),
            stamp: authority.stamp().clone(),
            attempt,
        });
        ScopeBatchCoordinator::open_port(port, authority, self.0.config.scheduler.clone(), class)
            .await
    }

    /// Read an exact batch result, including a predecessor's uncertain attempt.
    /// This observation never issues authority or resubmits the old operation.
    pub async fn batch_outcome(
        &self,
        target: &ScopeBatchAttempt,
        class: ScopeWorkClass,
        attempt: Duration,
    ) -> Result<ScopeBatchLookup, ScopeBatchError> {
        if target.stamp().scope() != &self.0.config.scope {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let wire_class = data_class(class)?;
        if attempt.is_zero() {
            return Err(ScopeBatchError::InvalidRequest);
        }
        let _running = self.batch_read_permit(class).await?;
        let payload = self
            .batch_read(
                Method::BatchLookup,
                wire_class,
                target.encode_canonical()?,
                attempt,
            )
            .await?;
        lookup_response(payload, target)
    }

    async fn batch_read_permit(
        &self,
        class: ScopeWorkClass,
    ) -> Result<opc_session_store::scope_scheduler::ScopeWorkPermit, ScopeBatchError> {
        self.0
            .config
            .scheduler
            .reserve(
                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                    &self.0.config.scope,
                ),
                class,
            )
            .await
            .map_err(|_| ScopeBatchError::Unavailable)?
            .start()
            .await
            .map_err(|_| ScopeBatchError::Unavailable)
    }

    async fn batch_read(
        &self,
        method: Method,
        class: Class,
        canonical: Vec<u8>,
        attempt: Duration,
    ) -> Result<ResultPayload, ScopeBatchError> {
        let id = super::super::boot::random_nonzero().map_err(|_| ScopeBatchError::Unavailable)?;
        let digest = transport_request_digest(method, &id, &canonical)
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        Ok(self
            .roundtrip(method, class, id, digest, &canonical, None, attempt)
            .await
            .map_err(batch_error)?
            .payload)
    }
}

// Only the factory above constructs this port. Every later call is made by the
// core coordinator while it owns the lane and its original running reservation.
struct BatchPort {
    client: ScopeClient,
    stamp: ScopeAuthorityStamp,
    attempt: Duration,
}

#[async_trait::async_trait]
impl ScopeBatchPort for BatchPort {
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        let payload = self
            .client
            .batch_read(
                Method::BatchReopen,
                data_class(class)?,
                self.stamp.encode_canonical()?,
                self.attempt,
            )
            .await?;
        if payload.status != ResultStatus::CurrentView || payload.own_execution != [0; 32] {
            return Err(batch_payload_error(&payload));
        }
        let cut = ScopeBatchReopen::decode_canonical(&payload.body)
            .map_err(|_| ScopeBatchError::OutcomeUnknown)?;
        if matches!(&cut, ScopeBatchReopen::Initialized(view) if view.authority().scope() != self.stamp.scope())
        {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        Ok(cut)
    }

    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        if request.stamp() != &self.stamp {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let class = data_class(class)?;
        let canonical = request.encode_canonical()?;
        let _active = self
            .client
            .0
            .config
            .process
            .gate
            .enter()
            .await
            .map_err(|_| ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))?;
        let payload = self
            .client
            .roundtrip(
                Method::ApplyBatch,
                class,
                *request.request_id(),
                request.digest()?,
                &canonical,
                None,
                self.attempt,
            )
            .await
            .map_err(batch_error)?
            .payload;
        if payload.status != ResultStatus::Committed {
            return Err(batch_payload_error(&payload));
        }
        if payload.own_execution != self.stamp.execution().transport_digest()? {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        let outcome = ScopeBatchOutcome::decode_canonical(&payload.body)
            .map_err(|_| ScopeBatchError::OutcomeUnknown)?;
        if !outcome.matches_request(request) {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        Ok(outcome)
    }

    async fn cancel(
        &self,
        target: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        if target.stamp() != &self.stamp {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let class = data_class(class)?;
        let canonical = target.encode_canonical()?;
        let _active = self
            .client
            .0
            .config
            .process
            .gate
            .enter()
            .await
            .map_err(|_| ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))?;
        let payload = self
            .client
            .roundtrip(
                Method::BatchCancel,
                class,
                *target.request_id(),
                target.cancellation_digest()?,
                &canonical,
                None,
                self.attempt,
            )
            .await
            .map_err(batch_error)?
            .payload;
        if payload.status != ResultStatus::Committed {
            return Err(batch_payload_error(&payload));
        }
        if payload.own_execution != self.stamp.execution().transport_digest()? {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        let receipt = ScopeBatchReceipt::decode_canonical(&payload.body)
            .map_err(|_| ScopeBatchError::OutcomeUnknown)?;
        if receipt.attempt() != target {
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        Ok(receipt)
    }
}

pub(in crate::scope) fn data_class(class: ScopeWorkClass) -> Result<Class, ScopeBatchError> {
    Ok(match class {
        ScopeWorkClass::Emergency => Class::Emergency,
        ScopeWorkClass::EmergencyClassification => Class::EmergencyClassification,
        ScopeWorkClass::Normal => Class::Normal,
        ScopeWorkClass::Maintenance => Class::Maintenance,
        ScopeWorkClass::SafetyControl => return Err(ScopeAuthorityError::Unauthorized.into()),
        _ => return Err(ScopeBatchError::InvalidRequest),
    })
}

pub(in crate::scope) fn batch_error(error: ScopeRpcError) -> ScopeBatchError {
    match error {
        ScopeRpcError::Invalid => ScopeBatchError::InvalidRequest,
        ScopeRpcError::Retry | ScopeRpcError::AuthTimeUnavailable => ScopeBatchError::Unavailable,
        ScopeRpcError::Unauthorized => ScopeAuthorityError::Unauthorized.into(),
        ScopeRpcError::Closed | ScopeRpcError::Superseded => {
            ScopeAuthorityError::StaleAuthority.into()
        }
        ScopeRpcError::Retired => ScopeAuthorityError::Retired.into(),
        ScopeRpcError::ProfileUnavailable => ScopeAuthorityError::ProfileNotActivated.into(),
        _ => ScopeBatchError::OutcomeUnknown,
    }
}

fn batch_payload_error(payload: &ResultPayload) -> ScopeBatchError {
    if payload.status == ResultStatus::BatchError && payload.own_execution == [0; 32] {
        return ScopeBatchError::decode_canonical(&payload.body)
            .unwrap_or(ScopeBatchError::OutcomeUnknown);
    }
    payload_error(payload)
        .map(batch_error)
        .unwrap_or(ScopeBatchError::OutcomeUnknown)
}

pub(in crate::scope) fn lookup_response(
    payload: ResultPayload,
    target: &ScopeBatchAttempt,
) -> Result<ScopeBatchLookup, ScopeBatchError> {
    if payload.status != ResultStatus::CurrentView || payload.own_execution != [0; 32] {
        return Err(batch_payload_error(&payload));
    }
    let outcome = ScopeBatchLookup::decode_canonical(&payload.body)
        .map_err(|_| ScopeBatchError::OutcomeUnknown)?;
    if matches!(&outcome, ScopeBatchLookup::Applied(applied) if !applied.matches_attempt(target)) {
        return Err(ScopeBatchError::OutcomeUnknown);
    }
    Ok(outcome)
}
