//! SQLite parity for the native reserved scope-row collection.

use super::*;
use crate::scope_authority::{ScopeAuthorityError, ScopeProfileActivation};
use crate::scope_batch::{ScopeBatchCommand, ScopeBatchError};
use crate::scope_storage::{self, ScopeRow};

pub(crate) fn operation(intent: &SessionMutationIntent) -> Option<&ScopeBatchCommand> {
    match intent {
        SessionMutationIntent::ScopeBatch(operation) => Some(operation),
        SessionMutationIntent::Authorized { mutation, .. } => match mutation.as_ref() {
            SessionMutationIntent::ScopeBatch(operation) => Some(operation),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn read(
    conn: &Connection,
    key: &crate::SessionKey,
) -> Result<Option<ScopeRow>, StoreError> {
    ops::get_raw_sync(conn, key)?
        .as_ref()
        .map(ScopeRow::from_record)
        .transpose()
        .map_err(|_| StoreError::BackendUnavailable("scope record invalid".into()))
}

pub(super) fn validate_links(
    conn: &Connection,
    record: &crate::StoredSessionRecord,
) -> io::Result<()> {
    if crate::scope_authority::is_scope_authority_key(&record.key) {
        let authority = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(record)
            .and_then(|checkpoint| checkpoint.state())
            .map_err(|_| invalid_data("scope authority invalid"))?;
        let key = scope_storage::batch_key(authority.view.scope())
            .map_err(|_| invalid_data("scope ledger key invalid"))?;
        return match read(conn, &key).map_err(|_| invalid_data("scope ledger read failed"))? {
            Some(ScopeRow::Batch(row)) if &row.scope == authority.view.scope() => Ok(()),
            _ => Err(invalid_data("scope required ledger absent or invalid")),
        };
    }
    let row = ScopeRow::from_record(record).map_err(|_| invalid_data("scope record invalid"))?;
    if let Some(scope) = row.scope() {
        let key = scope
            .key()
            .map_err(|_| invalid_data("scope authority key invalid"))?;
        let authority = ops::get_raw_sync(conn, &key)
            .map_err(|_| invalid_data("scope authority read failed"))?
            .ok_or_else(|| invalid_data("scope batch authority absent"))?;
        let authority = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(&authority)
            .and_then(|row| row.state())
            .map_err(|_| invalid_data("scope batch authority invalid"))?;
        if authority.view.scope() != scope {
            return Err(invalid_data("scope batch authority differs"));
        }
    }
    row.validate_links(&|key| read(conn, key).map_err(|_| ScopeBatchError::FormatMismatch))
        .map_err(|_| invalid_data("scope batch links invalid"))
}

/// Snapshot installation cannot erase retained authority, birth or generation
/// floors. This initial profile has no physical scope-row deletion operation.
pub(super) fn validate_snapshot_preserves_scopes(conn: &Connection) -> io::Result<()> {
    fn decode(row: &rusqlite::Row<'_>, offset: usize) -> io::Result<crate::StoredSessionRecord> {
        ops::stored_record_from_row(
            row.get(offset).map_err(db_error)?,
            row.get(offset + 1).map_err(db_error)?,
            row.get(offset + 2).map_err(db_error)?,
            row.get(offset + 3).map_err(db_error)?,
            row.get(offset + 4).map_err(db_error)?,
            row.get(offset + 5).map_err(db_error)?,
            row.get(offset + 6).map_err(db_error)?,
            row.get(offset + 7).map_err(db_error)?,
            row.get(offset + 8).map_err(db_error)?,
            row.get(offset + 9).map_err(db_error)?,
            row.get(offset + 10).map_err(db_error)?,
            row.get(offset + 11).map_err(db_error)?,
        )
        .map_err(|_| invalid_data("scope snapshot row invalid"))
    }
    let mut statement = conn.prepare(
        "SELECT old.tenant,old.nf_kind,old.key_type,old.stable_id,old.generation,old.owner,old.fence,old.state_class,old.state_type,old.expires_at,old.payload,old.encoding,\
                new.tenant,new.nf_kind,new.key_type,new.stable_id,new.generation,new.owner,new.fence,new.state_class,new.state_type,new.expires_at,new.payload,new.encoding \
         FROM main.session_records old LEFT JOIN consensus_incoming.session_records new \
         ON new.tenant=old.tenant AND new.nf_kind=old.nf_kind AND new.key_type=old.key_type AND new.stable_id=old.stable_id \
         WHERE old.key_type IN (?1,?2,?3,?4,?5,?6,?7)"
    ).map_err(db_error)?;
    let mut rows = statement
        .query(scope_storage::RESERVED_KEY_TYPES)
        .map_err(db_error)?;
    while let Some(row) = rows.next().map_err(db_error)? {
        if matches!(
            row.get_ref(12).map_err(db_error)?,
            rusqlite::types::ValueRef::Null
        ) {
            return Err(invalid_data("scope snapshot removes retained floor"));
        }
        let old = decode(row, 0)?;
        let new = decode(row, 12)?;
        let preserved = if crate::scope_authority::is_scope_authority_key(&old.key) {
            let old = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(&old)
                .map_err(|_| invalid_data("scope snapshot authority invalid"))?;
            let new = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(&new)
                .map_err(|_| invalid_data("scope snapshot authority invalid"))?;
            new.can_replace(&old)
        } else {
            let old = ScopeRow::from_record(&old)
                .and_then(|row| row.facts())
                .map_err(|_| invalid_data("scope snapshot floor invalid"))?;
            let new = ScopeRow::from_record(&new)
                .and_then(|row| row.facts())
                .map_err(|_| invalid_data("scope snapshot floor invalid"))?;
            new.can_replace(old)
        };
        if !preserved {
            return Err(invalid_data("scope snapshot regresses retained floor"));
        }
    }
    Ok(())
}

fn certificate_matches(
    scope: &MembershipValidationScope,
    certificate: &ScopeProfileActivation,
) -> bool {
    scope
        .application_authority_members
        .first()
        .is_some_and(|origin| application_authority_matches(scope, *origin, certificate.identity))
        && certificate.matches(
            certificate.identity,
            fenced_transition_voter_set_digest(
                certificate.identity,
                &scope.application_authority_members,
            ),
        )
}

pub(super) fn active(
    conn: &Connection,
    scope: &MembershipValidationScope,
) -> Result<bool, StoreError> {
    let key = scope_storage::profile_key(scope.current_identity.cluster_id())
        .map_err(|_| StoreError::BackendUnavailable("scope profile key invalid".into()))?;
    Ok(
        matches!(read(conn, &key)?, Some(ScopeRow::Activation(certificate)) if certificate_matches(scope, &certificate)),
    )
}

pub(super) fn activate(
    conn: &Connection,
    certificate: &ScopeProfileActivation,
) -> Result<(), StoreError> {
    let identity = read_identity_for_recovery_sync(conn)?;
    let scope = read_membership_scope_sync(conn, identity).map_err(|_| {
        StoreError::BackendUnavailable("scope activation authority unavailable".into())
    })?;
    // Durable Prepare fixes the formats that must be certified before cutover.
    // A candidate's provisional bootstrap scope precedes historical replay;
    // it must apply that old prefix exactly as the current voters did.
    if scope
        .pending
        .as_ref()
        .is_some_and(|pending| pending.transition_start_log_index != 0)
    {
        return Err(StoreError::TopologyAuthorityRevoked);
    }
    if !certificate_matches(&scope, certificate) {
        return Err(StoreError::CapabilityNotSupported(
            "scope_store_profile_v4".into(),
        ));
    }
    let record = ScopeRow::Activation(certificate.clone())
        .to_record()
        .map_err(|_| StoreError::BackendUnavailable("scope activation record invalid".into()))?;
    ops::insert_or_replace_scope_record_sync(conn, &record)
}

fn plan(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    operation: &ScopeBatchCommand,
) -> io::Result<Result<crate::scope_batch::state::ScopeBatchPlan, ScopeBatchError>> {
    let scope = operation.request.scope();
    let (legacy, current) = super::scope_authority::read(conn, identity, scope)
        .map_err(|_| invalid_data("scope batch authority read failed"))?;
    if legacy {
        return Ok(Err(ScopeBatchError::FormatMismatch));
    }
    // Before initial admission there is no authority or stable checkpoint.
    // Match native apply before inspecting the checkpoint, whose absence is
    // corruption only after authority has been admitted.
    if current.is_none() {
        return Ok(Err(
            crate::scope_authority::ScopeAuthorityError::StaleAuthority.into(),
        ));
    }
    let authority = match crate::scope_authority::checkpoint_state(scope, current) {
        Ok(authority) => authority,
        Err(error) => return Ok(Err(error.into())),
    };
    let checkpoint_key = scope_storage::batch_key(scope)
        .map_err(|_| invalid_data("scope batch checkpoint key invalid"))?;
    let checkpoint = match read(conn, &checkpoint_key)
        .map_err(|_| invalid_data("scope batch checkpoint read failed"))?
    {
        Some(ScopeRow::Batch(row)) if row.scope == *scope => *row,
        _ => return Ok(Err(ScopeBatchError::FormatMismatch)),
    };
    // The shared planner reports deterministic command refusals. A local
    // database/decode fault must escape that result and abort the transaction,
    // including its machine row and applied pointer, on this replica.
    let read_fault = std::cell::RefCell::new(None);
    let result = operation.plan(&authority, &checkpoint, |key| {
        read(conn, key).map_err(|error| {
            read_fault.borrow_mut().get_or_insert(error);
            ScopeBatchError::Unavailable
        })
    });
    if read_fault.into_inner().is_some() {
        return Err(invalid_data("scope batch row read failed"));
    }
    Ok(result)
}

pub(super) fn apply(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    scope: &MembershipValidationScope,
    command: &SessionConsensusCommand,
    index: u64,
    machine: &mut (u64, SessionConsensusEntryDigest, Option<Timestamp>, u64),
) -> io::Result<SessionConsensusResponse> {
    let operation = operation(&command.intent).ok_or_else(|| invalid_data("scope batch absent"))?;
    let authorized = matches!(&command.intent, SessionMutationIntent::Authorized { origin, authority_identity, .. }
        if application_authority_matches(scope, *origin, *authority_identity));
    let now = machine
        .2
        .map_or(command.logical_time, |time| time.max(command.logical_time));
    let result = if operation.request.scope().store() != identity.cluster_id() {
        Err(ScopeAuthorityError::Unauthorized.into())
    } else if !authorized {
        Err(
            super::scope_authority::authority_error(command, scope.application_authority_epoch)
                .into(),
        )
    } else if !active(conn, scope).map_err(|_| invalid_data("scope profile read failed"))? {
        Err(ScopeAuthorityError::ProfileNotActivated.into())
    } else {
        plan(conn, identity, operation)?
    };
    let outcome = match result {
        Ok(plan) => {
            let outcome = plan
                .checkpoint
                .outcome(operation.request.lane())
                .cloned()
                .ok_or_else(|| invalid_data("scope outcome absent"))?;
            let records: Result<Vec<_>, _> = plan.rows.values().map(ScopeRow::to_record).collect();
            for record in records.map_err(|_| invalid_data("scope batch record invalid"))? {
                ops::insert_or_replace_scope_record_sync(conn, &record)
                    .map_err(|_| invalid_data("scope batch write failed"))?;
            }
            Ok(outcome)
        }
        Err(error) => Err(error),
    };
    let sequence = machine
        .0
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| invalid_data("scope application sequence exhausted"))?;
    let digest = command
        .calculate_applied_digest(sequence, machine.1, now)
        .map_err(|_| invalid_data("scope batch digest invalid"))?;
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
    Ok(SessionConsensusResponse {
        result: Ok(SessionMutationOutcome::ScopeBatch(outcome)),
        sequence,
        digest: Some(digest),
        logical_time: Some(now),
        raft_log_index: index,
    })
}
