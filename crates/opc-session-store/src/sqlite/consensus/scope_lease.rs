//! Bounded authority rows in the reserved scope namespace. Ordinary request
//! receipt pruning cannot remove scope selection, grant, or replay floors.

use super::*;
use crate::scope_lease::{ScopeLeaseCommand, ScopeLeaseError, ScopeLeaseId};

pub(crate) type StoredCheckpoint = (bool, Option<([u8; 32], SessionConsensusResponse)>);

pub(crate) fn read(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    scope: &ScopeLeaseId,
) -> Result<StoredCheckpoint, StoreError> {
    let slot = scope
        .checkpoint_id()
        .map_err(|_| state_machine_intent_error())?;
    let key = scope.key().map_err(|_| state_machine_intent_error())?;
    // Receipt-backed checkpoints are a different stored profile. Crossing
    // this boundary is a fresh install; never interpret their absence as a
    // reset authority row or silently move an old grant into this namespace.
    let legacy = request_id_has_fenced_transition_receipt_sync(conn, identity, slot)?
        || conn
            .query_row(
                "SELECT 1 FROM consensus_request_outcomes WHERE request_id=?1",
                [slot.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| state_machine_intent_error())?
            .is_some();
    let current = ops::get_raw_sync(conn, &key)?
        .map(|record| {
            crate::scope_lease::ScopeLeaseCheckpoint::from_record(&record)
                .and_then(|checkpoint| checkpoint.stored())
        })
        .transpose()
        .map_err(|_| state_machine_intent_error())?;
    Ok((legacy, current))
}

fn state_machine_intent_error() -> StoreError {
    StoreError::BackendUnavailable("scope checkpoint read failed".into())
}

pub(crate) fn operation(intent: &SessionMutationIntent) -> Option<&ScopeLeaseCommand> {
    match intent {
        SessionMutationIntent::ScopeLease(operation) => Some(operation),
        SessionMutationIntent::Authorized { mutation, .. } => match mutation.as_ref() {
            SessionMutationIntent::ScopeLease(operation) => Some(operation),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn authority_error(
    command: &SessionConsensusCommand,
    current_epoch: SessionConsensusConfigurationEpoch,
) -> ScopeLeaseError {
    if matches!(
        &command.intent,
        SessionMutationIntent::Authorized { authority_identity, .. }
            if authority_identity.cluster_id() == command.identity.cluster_id()
                && authority_identity.configuration_epoch() < current_epoch
    ) {
        // The authenticated operation may have crossed a durable authority
        // switch after proposal. It has no effect; retry the exact request
        // through current admission instead of reporting a caller refusal.
        ScopeLeaseError::Unavailable
    } else {
        ScopeLeaseError::Unauthorized
    }
}

pub(super) fn apply(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
    command: &SessionConsensusCommand,
    index: u64,
    machine: &mut (u64, SessionConsensusEntryDigest, Option<Timestamp>, u64),
) -> io::Result<SessionConsensusResponse> {
    let operation =
        operation(&command.intent).ok_or_else(|| invalid_data("scope command absent"))?;
    let target = operation.request.scope();
    let authorized = match &command.intent {
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            ..
        } => application_authority_matches(scope, *origin, *authority_identity),
        _ => false,
    };
    let (legacy, current) =
        read(conn, identity, target).map_err(|_| invalid_data("scope checkpoint unavailable"))?;
    let result = if target.store() != identity.cluster_id() {
        Err(ScopeLeaseError::Unauthorized)
    } else if !authorized {
        Err(authority_error(command, scope.application_authority_epoch))
    } else if !super::scope_batch::active(conn, scope)
        .map_err(|_| invalid_data("scope activation unavailable"))?
    {
        Err(ScopeLeaseError::ProfileNotActivated)
    } else if legacy {
        Err(ScopeLeaseError::FormatMismatch)
    } else {
        operation.apply(current)
    };
    let sequence = machine
        .0
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid_data("scope application sequence exhausted"))?;
    let now = machine
        .2
        .map_or(command.logical_time, |time| time.max(command.logical_time));
    let digest = command
        .calculate_applied_digest(sequence, machine.1, now)
        .map_err(|_| invalid_data("scope digest invalid"))?;
    let response = SessionConsensusResponse {
        result: Ok(SessionMutationOutcome::ScopeLease(result.clone())),
        sequence,
        digest: Some(digest),
        logical_time: Some(now),
        raft_log_index: index,
    };
    if let Ok(checkpoint) = result {
        let record = checkpoint
            .to_record()
            .map_err(|_| invalid_data("scope checkpoint invalid"))?;
        ops::insert_or_replace_scope_record_sync(conn, &record)
            .map_err(|_| invalid_data("scope checkpoint write failed"))?;
    }
    let changed = conn.execute(
        "UPDATE consensus_machine SET application_sequence=?1,last_digest=?2,logical_time=?3 WHERE singleton=1 AND configuration_epoch=?4",
        params![checked_positive_i64(sequence)?, digest.as_bytes().as_slice(), ops::format_rfc3339_normalized(now), epoch_i64(identity)?],
    ).map_err(db_error)?;
    if changed != 1 {
        return Err(invalid_data("scope machine state absent"));
    }
    machine.0 = sequence;
    machine.1 = digest;
    machine.2 = Some(now);
    Ok(response)
}
