//! Deterministic touched-key business effects. No I/O or SQL is performed here.

use super::*;
use crate::backend::ReplicationOp;
use crate::fenced_transition::{
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
};
use crate::model::FenceToken;

pub(super) struct BusinessEffect {
    pub(super) key: SessionKey,
    pub(super) value: NativeKeyState,
    pub(super) next_fence: u64,
    pub(super) next_credential: u64,
    pub(super) outcome: FencedTransitionOutcome,
    pub(super) replication: ReplicationOp,
}

pub(super) fn transition(
    request: &FencedTransitionV2Request,
    current: &NativeKeyState,
    frontiers: &NativeFrontiers,
    logical_time: Timestamp,
) -> Result<BusinessEffect, StoreError> {
    request.validate_at(logical_time)?;
    let effect = transition_parts(
        request.lease(),
        request.mutation(),
        current,
        frontiers,
        logical_time,
    )?;
    if !effect.outcome.matches_v2_request(request) {
        return Err(StoreError::BackendUnavailable(
            "native transition outcome differs from original request".into(),
        ));
    }
    Ok(effect)
}

pub(super) fn transition_v1(
    request: &crate::FencedTransitionRequest,
    current: &NativeKeyState,
    frontiers: &NativeFrontiers,
    logical_time: Timestamp,
) -> Result<BusinessEffect, StoreError> {
    request.validate_at(logical_time)?;
    let effect = transition_parts(
        request.lease(),
        request.mutation(),
        current,
        frontiers,
        logical_time,
    )?;
    if !effect.outcome.matches_request_at(request, logical_time) {
        return Err(StoreError::BackendUnavailable(
            "native V1 outcome differs from original request".into(),
        ));
    }
    Ok(effect)
}

fn transition_parts(
    lease: &FencedTransitionLease,
    mutation: &FencedTransitionMutation,
    current: &NativeKeyState,
    frontiers: &NativeFrontiers,
    logical_time: Timestamp,
) -> Result<BusinessEffect, StoreError> {
    if let Some(record) = mutation.record() {
        // This existing helper only validates the typed encrypted envelope.
        crate::sqlite::validate_consensus_record(record)?;
    }
    match lease {
        FencedTransitionLease::Acquire { expected_fence, .. } => {
            if current.fence != expected_fence.get() {
                return Err(StoreError::StaleFence);
            }
        }
        FencedTransitionLease::Renew { lease, .. } => {
            if lease.expires_at() <= logical_time {
                return Err(StoreError::LeaseExpired);
            }
            if !current
                .lease
                .as_ref()
                .is_some_and(|stored| stored.matches(lease))
            {
                return Err(StoreError::StaleFence);
            }
        }
    }
    let live = current
        .record
        .as_ref()
        .filter(|record| record.expires_at.is_none_or(|until| until > logical_time));
    match (mutation.expected_generation(), live) {
        (None, None) => {}
        (Some(expected), Some(record)) if record.generation == expected => {}
        _ => return Err(StoreError::CasConflict),
    }
    if matches!(lease, FencedTransitionLease::Renew { .. })
        && mutation.expected_generation().is_some()
    {
        let record = live.ok_or(StoreError::CasConflict)?;
        if record.owner != *lease.owner() || record.fence != lease.committed_fence()? {
            return Err(StoreError::StaleFence);
        }
    }
    if matches!(lease, FencedTransitionLease::Acquire { .. })
        && current
            .lease
            .as_ref()
            .is_some_and(|lease| lease.active && lease.guard_expires_at > logical_time)
    {
        return Err(StoreError::LeaseHeld);
    }
    if current.reserved {
        return Err(StoreError::SessionRecordReserved);
    }
    // Preserve the existing signed deterministic horizon and error precedence
    // even though the native representation itself can hold a larger u64.
    if mutation.record().is_some_and(|record| {
        record.generation.get() > COUNTER_MAX || record.fence.get() > COUNTER_MAX
    }) || frontiers.restore_revision >= COUNTER_MAX
        || frontiers.watch_sequence >= COUNTER_MAX
    {
        return Err(StoreError::FencedTransitionStorageExhausted);
    }
    if let FencedTransitionLease::Acquire { expected_fence, .. } = lease {
        if expected_fence.get() > COUNTER_MAX - 2 || frontiers.next_credential >= COUNTER_MAX {
            return Err(StoreError::FencedTransitionStorageExhausted);
        }
        if frontiers.next_fence == 0 || frontiers.next_credential == 0 {
            return Err(StoreError::BackendUnavailable(
                "native lease frontier invalid".into(),
            ));
        }
    }
    let expires_at = crate::ttl::checked_session_deadline(logical_time, lease.ttl())?;
    let mut next_fence = frontiers.next_fence;
    let mut next_credential = frontiers.next_credential;
    let (guard, lease_replication) = match lease {
        FencedTransitionLease::Acquire {
            key,
            owner,
            expected_fence,
            ttl,
        } => {
            let fence = FenceToken::new(expected_fence.get() + 1);
            let guard = LeaseGuard::new(
                key.clone(),
                owner.clone(),
                fence,
                logical_time,
                expires_at,
                next_credential,
            );
            next_fence = next_fence.max(fence.get() + 1);
            next_credential += 1;
            let replication = ReplicationOp::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                fence,
                credential_id: guard.credential_id(),
                ttl: *ttl,
                expires_at,
            };
            (guard, replication)
        }
        FencedTransitionLease::Renew { lease, ttl } => {
            let guard = LeaseGuard::new(
                lease.key().clone(),
                lease.owner().clone(),
                lease.fence(),
                lease.acquired_at(),
                expires_at,
                lease.credential_id(),
            );
            let replication = ReplicationOp::RenewLease {
                key: guard.key().clone(),
                owner: guard.owner().clone(),
                fence: guard.fence(),
                credential_id: guard.credential_id(),
                ttl: *ttl,
                expires_at,
            };
            (guard, replication)
        }
    };
    let mut value = current.clone();
    value.fence = guard.fence().get();
    value.lease = Some(NativeLease::from_guard(&guard)?);
    let (generation, mutation, replication) = match mutation {
        FencedTransitionMutation::Create { record }
        | FencedTransitionMutation::Update { record, .. } => {
            value.record = Some(record.as_ref().clone());
            let mutation_result = if matches!(mutation, FencedTransitionMutation::Create { .. }) {
                FencedTransitionMutationResult::Created
            } else {
                FencedTransitionMutationResult::Updated
            };
            (
                record.generation,
                mutation_result,
                ReplicationOp::CompareAndSet {
                    key: record.key.clone(),
                    expected_generation: mutation.expected_generation(),
                    credential_id: guard.credential_id(),
                    guard_expires_at: guard.expires_at(),
                    new_record: record.as_ref().clone(),
                },
            )
        }
        FencedTransitionMutation::Delete {
            expected_generation,
        } => {
            value.record = None;
            (
                *expected_generation,
                FencedTransitionMutationResult::Deleted,
                ReplicationOp::DeleteFenced {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                },
            )
        }
        FencedTransitionMutation::RefreshTtl {
            expected_generation,
            ttl,
        } => {
            let expires_at = crate::ttl::checked_session_deadline(logical_time, *ttl)?;
            let mut record = live.ok_or(StoreError::CasConflict)?.clone();
            record.expires_at = Some(expires_at);
            value.record = Some(record);
            (
                *expected_generation,
                FencedTransitionMutationResult::TtlRefreshed { expires_at },
                ReplicationOp::RefreshTtl {
                    key: guard.key().clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    ttl: *ttl,
                    expires_at,
                },
            )
        }
    };
    let outcome = FencedTransitionOutcome::new(guard, generation, mutation, logical_time)?;
    let replication = ReplicationOp::Batch {
        ops: vec![lease_replication, replication],
    };
    replication.validate_structure()?;
    Ok(BusinessEffect {
        key: lease.key().clone(),
        value,
        next_fence,
        next_credential,
        outcome,
        replication,
    })
}

pub(super) fn deterministic(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::NotFound
            | StoreError::StaleFence
            | StoreError::CasConflict
            | StoreError::InvalidKey(_)
            | StoreError::TopologyAuthorityRevoked
            | StoreError::InvalidSessionTtl
            | StoreError::InvalidRecordExpiry
            | StoreError::LeaseHeld
            | StoreError::LeaseExpired
            | StoreError::SessionRecordReserved
            | StoreError::PayloadTooLarge { .. }
            | StoreError::FencedTransitionRequestExpired
            | StoreError::FencedTransitionStorageExhausted
    )
}
