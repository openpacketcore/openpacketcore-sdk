//! Bounded authority rows in the reserved scope namespace. Ordinary request
//! receipt pruning cannot remove scope selection, grant, or replay floors.

use super::*;
use crate::scope_authority::{ScopeAuthorityCommand, ScopeAuthorityError, ScopeId};

pub(crate) type StoredCheckpoint = (bool, Option<([u8; 32], SessionConsensusResponse)>);

pub(crate) fn read(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    scope: &ScopeId,
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
            super::scope_batch::validate_links(conn, &record)
                .map_err(|_| ScopeAuthorityError::FormatMismatch)?;
            crate::scope_authority::ScopeAuthorityCheckpoint::from_record(&record)
                .and_then(|checkpoint| checkpoint.stored())
        })
        .transpose()
        .map_err(|_| state_machine_intent_error())?;
    Ok((legacy, current))
}

fn has_scope_rows(conn: &Connection, scope: &ScopeId) -> io::Result<bool> {
    let mut statement = conn.prepare("SELECT key_type,stable_id FROM session_records WHERE tenant=?1 AND nf_kind=?2 AND key_type IN ('opc-scope-lease','opc-scope-batch','opc-scope-child','opc-scope-claim')").map_err(db_error)?;
    let mut rows = statement
        .query(params![scope.tenant().as_str(), scope.nf_kind().as_str()])
        .map_err(db_error)?;
    while let Some(row) = rows.next().map_err(db_error)? {
        let kind: String = row.get(0).map_err(db_error)?;
        let bytes: Vec<u8> = row.get(1).map_err(db_error)?;
        if kind == "opc-scope-lease" && bytes.as_slice() == scope.slot() {
            return Ok(true);
        }
        if kind == "opc-scope-lease" {
            continue;
        }
        let key = crate::SessionKey {
            tenant: scope.tenant().clone(),
            nf_kind: scope.nf_kind().clone(),
            key_type: crate::SessionKeyType::other(kind)
                .map_err(|_| invalid_data("scope orphan key invalid"))?,
            stable_id: crate::StableId::new(bytes::Bytes::from(bytes))
                .map_err(|_| invalid_data("scope orphan key invalid"))?,
        };
        let record = ops::get_raw_sync(conn, &key)
            .map_err(|_| invalid_data("scope orphan read failed"))?
            .ok_or_else(|| invalid_data("scope orphan row absent"))?;
        let row = crate::scope_storage::ScopeRow::from_record(&record)
            .map_err(|_| invalid_data("scope orphan row invalid"))?;
        if row.scope() == Some(scope) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn state_machine_intent_error() -> StoreError {
    StoreError::BackendUnavailable("scope checkpoint read failed".into())
}

pub(crate) fn operation(intent: &SessionMutationIntent) -> Option<&ScopeAuthorityCommand> {
    match intent {
        SessionMutationIntent::ScopeAuthority(operation) => Some(operation),
        SessionMutationIntent::Authorized { mutation, .. } => match mutation.as_ref() {
            SessionMutationIntent::ScopeAuthority(operation) => Some(operation),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn authority_error(
    command: &SessionConsensusCommand,
    current_epoch: SessionConsensusConfigurationEpoch,
) -> ScopeAuthorityError {
    if matches!(
        &command.intent,
        SessionMutationIntent::Authorized { authority_identity, .. }
            if authority_identity.cluster_id() == command.identity.cluster_id()
                && authority_identity.configuration_epoch() < current_epoch
    ) {
        // The authenticated operation may have crossed a durable authority
        // switch after proposal. It has no effect; retry the exact request
        // through current admission instead of reporting a caller refusal.
        ScopeAuthorityError::Unavailable
    } else {
        ScopeAuthorityError::Unauthorized
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
    let initialize_ledger = current.is_none();
    let result = if target.store() != identity.cluster_id() {
        Err(ScopeAuthorityError::Unauthorized)
    } else if !authorized {
        Err(authority_error(command, scope.application_authority_epoch))
    } else if !super::scope_batch::active(conn, scope)
        .map_err(|_| invalid_data("scope activation unavailable"))?
    {
        Err(ScopeAuthorityError::ProfileNotActivated)
    } else if legacy || (current.is_none() && has_scope_rows(conn, target)?) {
        Err(ScopeAuthorityError::FormatMismatch)
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
        result: Ok(SessionMutationOutcome::ScopeAuthority(result.clone())),
        sequence,
        digest: Some(digest),
        logical_time: Some(now),
        raft_log_index: index,
    };
    if let Ok(checkpoint) = result {
        if initialize_ledger {
            let ledger = crate::scope_storage::ScopeRow::Batch(Box::new(
                crate::scope_batch::ScopeBatchCheckpoint::empty(target.clone()),
            ))
            .to_record()
            .map_err(|_| invalid_data("scope initial ledger invalid"))?;
            ops::insert_or_replace_scope_record_sync(conn, &ledger)
                .map_err(|_| invalid_data("scope initial ledger write failed"))?;
        }
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
