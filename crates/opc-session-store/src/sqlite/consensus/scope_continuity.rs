//! The profile certificate and membership cutover share one transaction.

use super::*;
use crate::scope_lease::{ScopeProfileActivation, ScopeProfileContinuation};
use crate::scope_storage::{self, ContinuationRow, ScopeRow};

fn expected(
    scope: &MembershipValidationScope,
) -> Result<ScopeProfileContinuation, MembershipScopeMutationError> {
    let pending = scope
        .pending
        .as_ref()
        .ok_or(MembershipScopeMutationError::ConflictingTransition)?;
    Ok(ScopeProfileContinuation {
        transition_id: pending.transition_id,
        transition_digest: pending.transition_digest,
        predecessor: ScopeProfileActivation::new(
            scope.current_identity,
            fenced_transition_voter_set_digest(scope.current_identity, &scope.current_members),
        ),
        successor: ScopeProfileActivation::new(
            pending.desired_identity,
            fenced_transition_voter_set_digest(pending.desired_identity, &pending.desired_members),
        ),
    })
}

fn activation(
    conn: &Connection,
    scope: &MembershipValidationScope,
) -> Result<Option<ScopeProfileActivation>, MembershipScopeMutationError> {
    let key = scope_storage::profile_key(scope.current_identity.cluster_id())
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    match scope_batch::read(conn, &key).map_err(|_| MembershipScopeMutationError::CorruptState)? {
        None => Ok(None),
        Some(ScopeRow::Activation(certificate))
            if certificate.matches(
                scope.current_identity,
                fenced_transition_voter_set_digest(scope.current_identity, &scope.current_members),
            ) =>
        {
            Ok(Some(certificate))
        }
        _ => Err(MembershipScopeMutationError::CorruptState),
    }
}

/// Persist the checked exact transition independently of ordinary receipt
/// retention. A subsequent leader can resume from this committed evidence.
pub(super) fn certify(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
    certificate: &ScopeProfileContinuation,
    log_index: u64,
) -> Result<MembershipScopeMutation, MembershipScopeMutationError> {
    let scope = read_scope_for_mutation(conn, storage_identity)?;
    let expected = expected(&scope)?;
    if certificate.validate().is_err()
        || *certificate != expected
        || activation(conn, &scope)?.as_ref() != Some(&certificate.predecessor)
        || log_index <= scope.pending.as_ref().unwrap().transition_start_log_index
    {
        return Err(MembershipScopeMutationError::InvalidScope);
    }
    let key = scope_storage::continuation_key(storage_identity.cluster_id())
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    let retained =
        scope_batch::read(conn, &key).map_err(|_| MembershipScopeMutationError::CorruptState)?;
    if matches!(&retained, Some(ScopeRow::Continuation(row)) if row.certificate == *certificate) {
        return Ok(MembershipScopeMutation::Idempotent);
    }
    if scope.application_authority_epoch != scope.current_identity.configuration_epoch()
        || scope.application_authority_members != scope.current_members
    {
        return Err(MembershipScopeMutationError::TransitionNotQuiescent);
    }
    let row = ScopeRow::Continuation(Box::new(ContinuationRow {
        certificate: certificate.clone(),
        log_index,
    }));
    if let Some(before) = retained {
        if !row
            .facts()
            .map_err(|_| MembershipScopeMutationError::CorruptState)?
            .can_replace(
                before
                    .facts()
                    .map_err(|_| MembershipScopeMutationError::CorruptState)?,
            )
        {
            return Err(MembershipScopeMutationError::CorruptState);
        }
    }
    let record = row
        .to_record()
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    ops::insert_or_replace_scope_record_sync(conn, &record)
        .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    Ok(MembershipScopeMutation::Applied)
}

/// An activated predecessor cannot fence authority or promote voters without
/// its exact durable continuation. Missing or mismatched decodable evidence is
/// a deterministic refusal at the Fence; only read/decode faults abort apply.
/// A resumed Prepare may certify after the learner marker, before the Fence.
pub(super) fn require_for_pending(
    conn: &Connection,
    scope: &MembershipValidationScope,
) -> Result<Option<ScopeProfileContinuation>, MembershipScopeMutationError> {
    let Some(activation) = activation(conn, scope)? else {
        return Ok(None);
    };
    let expected = expected(scope)?;
    let pending = scope.pending.as_ref().unwrap();
    let key = scope_storage::continuation_key(scope.current_identity.cluster_id())
        .map_err(|_| MembershipScopeMutationError::CorruptState)?;
    match scope_batch::read(conn, &key).map_err(|_| MembershipScopeMutationError::CorruptState)? {
        Some(ScopeRow::Continuation(row))
            if row.certificate == expected
                && row.certificate.predecessor == activation
                && row.log_index > pending.transition_start_log_index =>
        {
            Ok(Some(expected))
        }
        _ => Err(MembershipScopeMutationError::InvalidScope),
    }
}

pub(super) fn carry_at_cutover(
    conn: &Connection,
    scope: &MembershipValidationScope,
) -> Result<(), MembershipScopeMutationError> {
    if let Some(certificate) = require_for_pending(conn, scope)? {
        let record = ScopeRow::Activation(certificate.successor)
            .to_record()
            .map_err(|_| MembershipScopeMutationError::CorruptState)?;
        ops::insert_or_replace_scope_record_sync(conn, &record)
            .map_err(|_| MembershipScopeMutationError::BackendUnavailable)?;
    }
    Ok(())
}
