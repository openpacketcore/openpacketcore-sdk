//! Original read-only consumer receipt decisions over one coherent ledger.
//! Storage adapters distinguish ordinary outcomes from permanent V1 bindings.

use super::*;

pub(crate) trait ConsumerReceiptStore {
    fn outcome(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>>;
    fn fenced(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError>;
    fn occupied(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError>;
}

impl ConsumerReceiptStore for &Connection {
    fn outcome(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
        read_outcome_sync(self, identity, id)
    }
    fn fenced(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError> {
        request_id_has_fenced_transition_receipt_sync(self, identity, id)
    }
    fn occupied(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError> {
        request_id_is_occupied_sync(self, identity, id)
    }
}

pub(crate) fn read_consumer_request_binding_sync(
    store: &impl ConsumerReceiptStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    binding_request_id: SessionConsensusRequestId,
    request_commitment: [u8; 32],
) -> Result<ConsumerRequestBindingLookup, StoreError> {
    let binding_digest = authorized_mutation_payload_digest(
        storage_identity,
        authority_identity,
        &SessionMutationIntent::BindConsumerRequest { request_commitment },
    )
    .map_err(|_| StoreError::BackendUnavailable("consumer binding lookup is unavailable".into()))?;
    match store
        .outcome(storage_identity, binding_request_id)
        .map_err(|_| {
            StoreError::BackendUnavailable("consumer binding lookup is unavailable".into())
        })? {
        Some((digest, response))
            if digest == binding_digest
                && matches!(&response.result, Ok(SessionMutationOutcome::Unit)) =>
        {
            Ok(ConsumerRequestBindingLookup::Matched(Box::new(response)))
        }
        Some(_) => Ok(ConsumerRequestBindingLookup::Conflict),
        None if store.fenced(storage_identity, binding_request_id)? => {
            Ok(ConsumerRequestBindingLookup::Conflict)
        }
        None => Ok(ConsumerRequestBindingLookup::Missing),
    }
}

pub(crate) fn read_consumer_lease_mutation_status_sync(
    store: &impl ConsumerReceiptStore,
    storage_identity: SessionConsensusIdentity,
    authority_identity: SessionConsensusIdentity,
    binding_request_id: SessionConsensusRequestId,
    operation_request_id: SessionConsensusRequestId,
    request: &crate::consumer::SessionConsumerRequest,
) -> Result<crate::consumer::SessionConsumerLeaseMutationStatus, StoreError> {
    use crate::consumer::{
        SessionConsumerLeaseMutationOperation, SessionConsumerLeaseMutationStatus,
        SessionConsumerOperation,
    };

    request.validate().map_err(|_| {
        StoreError::BackendUnavailable("consumer lease receipt status is unavailable".into())
    })?;
    if request.scope().consensus_identity() != authority_identity {
        return Err(StoreError::BackendUnavailable(
            "consumer lease receipt status is unavailable".into(),
        ));
    }
    let lease_operation = match request.operation() {
        SessionConsumerOperation::AcquireLease { key, owner, ttl } => {
            SessionConsumerLeaseMutationOperation::Acquire {
                key: key.clone(),
                owner: owner.clone(),
                ttl: *ttl,
            }
        }
        SessionConsumerOperation::RenewLease { lease, ttl } => {
            SessionConsumerLeaseMutationOperation::Renew {
                lease: lease.clone(),
                ttl: *ttl,
            }
        }
        SessionConsumerOperation::ReleaseLease { lease } => {
            SessionConsumerLeaseMutationOperation::Release {
                lease: lease.clone(),
            }
        }
        _ => {
            return Err(StoreError::BackendUnavailable(
                "consumer lease receipt status is unavailable".into(),
            ));
        }
    };
    let commitment = crate::consumer::consumer_request_commitment(request).map_err(|_| {
        StoreError::BackendUnavailable("consumer lease receipt status is unavailable".into())
    })?;
    let binding_digest = authorized_mutation_payload_digest(
        storage_identity,
        authority_identity,
        &SessionMutationIntent::BindConsumerRequest {
            request_commitment: commitment,
        },
    )
    .map_err(|_| {
        StoreError::BackendUnavailable("consumer lease receipt status is unavailable".into())
    })?;
    let operation_intent = match &lease_operation {
        SessionConsumerLeaseMutationOperation::Acquire { key, owner, ttl } => {
            SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: *ttl,
            }
        }
        SessionConsumerLeaseMutationOperation::Renew { lease, ttl } => {
            SessionMutationIntent::RenewLease {
                lease: lease.clone(),
                ttl: *ttl,
            }
        }
        SessionConsumerLeaseMutationOperation::Release { lease } => {
            SessionMutationIntent::ReleaseLease(lease.clone())
        }
    };
    let operation_digest =
        authorized_mutation_payload_digest(storage_identity, authority_identity, &operation_intent)
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "consumer lease receipt status is unavailable".into(),
                )
            })?;

    let binding = store
        .outcome(storage_identity, binding_request_id)
        .map_err(|_| {
            StoreError::BackendUnavailable("consumer lease receipt status is unavailable".into())
        })?;
    let binding_matches = match binding {
        Some((digest, response)) if digest == binding_digest => {
            matches!(response.result, Ok(SessionMutationOutcome::Unit))
        }
        Some(_) => return Ok(SessionConsumerLeaseMutationStatus::RequestConflict),
        None => false,
    };
    if !binding_matches {
        if store.occupied(storage_identity, binding_request_id)?
            || store.occupied(storage_identity, operation_request_id)?
        {
            return Ok(SessionConsumerLeaseMutationStatus::RequestConflict);
        }
        return Ok(SessionConsumerLeaseMutationStatus::NotFound);
    }

    let Some((digest, response)) = store
        .outcome(storage_identity, operation_request_id)
        .map_err(|_| {
            StoreError::BackendUnavailable("consumer lease receipt status is unavailable".into())
        })?
    else {
        if store.occupied(storage_identity, operation_request_id)? {
            return Ok(SessionConsumerLeaseMutationStatus::RequestConflict);
        }
        return Ok(SessionConsumerLeaseMutationStatus::NotFound);
    };
    if digest != operation_digest {
        return Ok(SessionConsumerLeaseMutationStatus::RequestConflict);
    }
    let recorded = consumer_lease_mutation_result_from_response(&lease_operation, &response)?;
    Ok(SessionConsumerLeaseMutationStatus::Recorded(Box::new(
        recorded,
    )))
}

pub(crate) fn read_consumer_compare_and_set_status_sync(
    store: &impl ConsumerReceiptStore,
    storage_identity: SessionConsensusIdentity,
    lookup: ConsumerCompareAndSetReceiptLookup,
) -> Result<crate::consumer::SessionConsumerCompareAndSetStatus, StoreError> {
    use crate::consumer::{
        SessionConsumerCompareAndSetReceiptOutcome, SessionConsumerCompareAndSetStatus,
        SessionConsumerStoreError,
    };

    let binding = store
        .outcome(storage_identity, lookup.binding_request_id)
        .map_err(|_| {
            StoreError::BackendUnavailable("consumer compare-and-set status is unavailable".into())
        })?;
    let binding_matches = match binding {
        Some((digest, response)) if digest == lookup.binding_digest => {
            matches!(response.result, Ok(SessionMutationOutcome::Unit))
        }
        Some(_) => return Ok(SessionConsumerCompareAndSetStatus::RequestConflict),
        None => false,
    };
    if !binding_matches {
        if store.fenced(storage_identity, lookup.binding_request_id)?
            || store.occupied(storage_identity, lookup.operation_request_id)?
        {
            return Ok(SessionConsumerCompareAndSetStatus::RequestConflict);
        }
        return Ok(SessionConsumerCompareAndSetStatus::NotFound);
    }

    let Some((digest, response)) = store
        .outcome(storage_identity, lookup.operation_request_id)
        .map_err(|_| {
            StoreError::BackendUnavailable("consumer compare-and-set status is unavailable".into())
        })?
    else {
        if store.fenced(storage_identity, lookup.operation_request_id)? {
            return Ok(SessionConsumerCompareAndSetStatus::RequestConflict);
        }
        return Ok(SessionConsumerCompareAndSetStatus::NotFound);
    };
    if digest != lookup.operation_digest {
        return Ok(SessionConsumerCompareAndSetStatus::RequestConflict);
    }
    let recorded = match response.result {
        Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success)) => {
            SessionConsumerCompareAndSetReceiptOutcome::Applied
        }
        Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict { .. })) => {
            SessionConsumerCompareAndSetReceiptOutcome::Conflict
        }
        Err(error) => SessionConsumerCompareAndSetReceiptOutcome::Rejected(
            SessionConsumerStoreError::from(error),
        ),
        Ok(_) => {
            return Err(StoreError::BackendUnavailable(
                "consumer compare-and-set status is unavailable".into(),
            ));
        }
    };
    Ok(SessionConsumerCompareAndSetStatus::Recorded(recorded))
}
