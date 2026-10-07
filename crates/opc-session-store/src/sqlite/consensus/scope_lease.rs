//! Bounded scope checkpoints share the durable keyed outcome collection, but
//! replace one scope key instead of appending operation receipt keys.

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
    let legacy = ops::get_raw_sync(conn, &key)?.is_some()
        || request_id_has_fenced_transition_receipt_sync(conn, identity, slot)?;
    let current =
        read_outcome_sync(conn, identity, slot).map_err(|_| state_machine_intent_error())?;
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
    let slot = target
        .checkpoint_id()
        .map_err(|_| invalid_data("scope key invalid"))?;
    let (legacy, current) =
        read(conn, identity, target).map_err(|_| invalid_data("scope checkpoint unavailable"))?;
    let result = if !authorized || target.store() != identity.cluster_id() {
        Err(ScopeLeaseError::Unauthorized)
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
        let checkpoint_digest = checkpoint
            .digest()
            .map_err(|_| invalid_data("scope checkpoint invalid"))?;
        conn.execute(
            "INSERT INTO consensus_request_outcomes(request_id,configuration_epoch,payload_digest,response_json) VALUES(?1,?2,?3,?4) ON CONFLICT(request_id) DO UPDATE SET payload_digest=excluded.payload_digest,response_json=excluded.response_json",
            params![slot.as_bytes().as_slice(), epoch_i64(identity)?, checkpoint_digest.as_slice(), encode_json(&response)?],
        ).map_err(db_error)?;
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
