//! One detached atomic child/claim/counter transition, with no ordinary receipt.

use super::*;
use crate::scope_authority::{ScopeAuthorityCheckpoint, ScopeAuthorityError};
use crate::scope_batch::{ScopeBatchCommand, ScopeBatchError};
use crate::scope_storage::{self, ScopeRow};

#[cfg(test)]
#[path = "scope_batch_tests.rs"]
mod tests;

pub(super) fn validate_replacement(
    key: &SessionKey,
    before: Option<&NativeKeyState>,
    after: Option<&NativeKeyState>,
) -> io::Result<()> {
    if !scope_storage::is_batch_record_key(key) {
        return Ok(());
    }
    if let Some(before) = before.and_then(|row| row.record.as_ref()) {
        let before = ScopeRow::from_record(before)
            .and_then(|row| row.facts())
            .map_err(|_| invalid("scope predecessor invalid"))?;
        let after = after
            .and_then(|row| row.record.as_ref())
            .ok_or_else(|| invalid("scope row cannot be pruned"))?;
        let after = ScopeRow::from_record(after)
            .and_then(|row| row.facts())
            .map_err(|_| invalid("scope successor invalid"))?;
        if !after.can_replace(before) {
            return Err(invalid("scope row floors regressed"));
        }
    }
    Ok(())
}

pub(super) fn validate_links<'a>(
    key: &SessionKey,
    read: impl Fn(&SessionKey) -> Option<&'a NativeKeyState>,
) -> io::Result<()> {
    if crate::scope_authority::is_scope_authority_key(key) {
        let record = read(key)
            .and_then(|row| row.record.as_ref())
            .ok_or_else(|| invalid("scope authority absent"))?;
        let authority = ScopeAuthorityCheckpoint::from_record(record)
            .and_then(|checkpoint| checkpoint.state())
            .map_err(|_| invalid("scope authority invalid"))?;
        let ledger_key = scope_storage::batch_key(authority.view.scope())
            .map_err(|_| invalid("scope ledger key invalid"))?;
        let ledger = read(&ledger_key)
            .and_then(|row| row.record.as_ref())
            .ok_or_else(|| invalid("scope required ledger absent"))?;
        return match ScopeRow::from_record(ledger) {
            Ok(ScopeRow::Batch(row)) if &row.scope == authority.view.scope() => Ok(()),
            _ => Err(invalid("scope required ledger invalid")),
        };
    }
    if !scope_storage::is_batch_record_key(key) {
        return Ok(());
    }
    let decode_row = |key: &SessionKey| {
        read(key)
            .and_then(|row| row.record.as_ref())
            .map(ScopeRow::from_record)
            .transpose()
    };
    let row = decode_row(key)
        .map_err(|_| invalid("scope linked row invalid"))?
        .ok_or_else(|| invalid("scope linked row missing"))?;
    if let Some(scope) = row.scope() {
        let authority_key = scope
            .key()
            .map_err(|_| invalid("scope authority key invalid"))?;
        let authority = read(&authority_key)
            .and_then(|row| row.record.as_ref())
            .ok_or_else(|| invalid("scope batch authority absent"))?;
        let authority = ScopeAuthorityCheckpoint::from_record(authority)
            .and_then(|row| row.state())
            .map_err(|_| invalid("scope batch authority invalid"))?;
        if authority.view.scope() != scope {
            return Err(invalid("scope batch authority differs"));
        }
    }
    row.validate_links(&decode_row)
        .map_err(|_| invalid("scope row links invalid"))
}

pub(super) fn validate_changed_links<'a>(
    key: &SessionKey,
    before: Option<&NativeKeyState>,
    read: impl Fn(&SessionKey) -> Option<&'a NativeKeyState>,
) -> io::Result<()> {
    validate_links(key, &read)?;
    if !scope_storage::is_batch_record_key(key) {
        return Ok(());
    }
    let old = before
        .and_then(|row| row.record.as_ref())
        .map(ScopeRow::from_record)
        .transpose()
        .map_err(|_| invalid("scope predecessor links invalid"))?;
    // Validate the final versions of the predecessor's neighbours as well:
    // omitting a claim release or stealing a claim cannot hide behind a valid
    // successor's smaller/different dependency set.
    let neighbours = match old {
        Some(ScopeRow::Child(child)) => child
            .claims
            .iter()
            .map(|claim| scope_storage::claim_key(&child.namespace, *claim))
            .collect::<Result<Vec<_>, _>>(),
        Some(ScopeRow::Claim(claim)) => claim
            .owner
            .map(|owner| scope_storage::child_key(&claim.namespace, owner.child))
            .transpose()
            .map(|key| key.into_iter().collect()),
        _ => Ok(Vec::new()),
    }
    .map_err(|_| invalid("scope neighbour key invalid"))?;
    for key in neighbours {
        validate_links(&key, &read)?;
    }
    Ok(())
}

fn decode(row: &NativeKeyState) -> Result<Option<ScopeRow>, ScopeBatchError> {
    if row.lease.is_some() || row.reserved || row.fence != 0 {
        return Err(ScopeBatchError::FormatMismatch);
    }
    row.record.as_ref().map(ScopeRow::from_record).transpose()
}

impl NativeState {
    pub(crate) fn scope_record(
        &self,
        identity: SessionConsensusIdentity,
        key: &SessionKey,
    ) -> Result<Option<ScopeRow>, StoreError> {
        self.require_business_proof().map_err(|_| unavailable())?;
        if self.identity != identity || !scope_storage::is_batch_record_key(key) {
            return Err(unavailable());
        }
        self.keys
            .get(key)
            .map(|row| decode(row))
            .transpose()
            .map(Option::flatten)
            .map_err(|_| unavailable())
    }
}

impl NativeDelta<'_> {
    pub(super) fn scope_profile_active(&self) -> io::Result<bool> {
        let key = scope_storage::profile_key(self.base.identity.cluster_id())
            .map_err(|_| invalid("scope profile key invalid"))?;
        let row =
            decode(&self.physical_key(&key)).map_err(|_| invalid("scope profile row invalid"))?;
        Ok(
            matches!(row, Some(ScopeRow::Activation(certificate)) if certificate.matches(self.base.identity,
            fenced_transition_voter_set_digest(self.base.identity, &self.base.members))),
        )
    }

    pub(super) fn scope_batch(
        &mut self,
        command: &SessionConsensusCommand,
        operation: &ScopeBatchCommand,
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        let scope = operation.request.scope();
        let result = if scope.store() != self.base.identity.cluster_id() {
            Err(ScopeAuthorityError::Unauthorized.into())
        } else if !authorized {
            Err(crate::sqlite::consensus::scope_authority::authority_error(
                command,
                self.base.identity.configuration_epoch(),
            )
            .into())
        } else if !self.scope_profile_active()? {
            Err(ScopeAuthorityError::ProfileNotActivated.into())
        } else {
            self.prepare_scope_batch(operation)
        };
        let outcome = match result {
            Ok(plan) => {
                let outcome = plan
                    .checkpoint
                    .outcome(operation.request.lane())
                    .cloned()
                    .ok_or_else(|| invalid("scope batch outcome absent"))?;
                // Finish every conversion before publishing any row into the
                // enclosing native delta. The WAL owner publishes that delta
                // only after its ordinary strict durability boundary.
                let rows: Result<Vec<_>, _> = plan
                    .rows
                    .into_iter()
                    .map(|(key, row)| {
                        Ok((
                            key,
                            NativeKeyState {
                                record: Some(row.to_record()?),
                                ..NativeKeyState::default()
                            },
                        ))
                    })
                    .collect::<Result<_, ScopeBatchError>>();
                self.keys
                    .extend(rows.map_err(|_| invalid("scope batch record invalid"))?);
                Ok(outcome)
            }
            Err(error) => Err(error),
        };
        let sequence = self
            .frontiers
            .sequence
            .checked_add(1)
            .filter(|value| *value <= COUNTER_MAX)
            .ok_or_else(|| invalid("scope application sequence exhausted"))?;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("scope batch digest invalid"))?;
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        Ok(self.response(index, Ok(SessionMutationOutcome::ScopeBatch(outcome))))
    }

    fn prepare_scope_batch(
        &self,
        operation: &ScopeBatchCommand,
    ) -> Result<crate::scope_batch::state::ScopeBatchPlan, ScopeBatchError> {
        let scope = operation.request.scope();
        if self.request_receipt(&scope.checkpoint_id()?).is_some() {
            return Err(ScopeBatchError::FormatMismatch);
        }
        let authority_key = scope.key()?;
        let authority = self
            .physical_key(&authority_key)
            .record
            .ok_or(ScopeAuthorityError::StaleAuthority)?;
        let authority = ScopeAuthorityCheckpoint::from_record(&authority)?.state()?;
        let row = decode(&self.physical_key(&scope_storage::batch_key(scope)?))?;
        let checkpoint = match row {
            Some(ScopeRow::Batch(row)) if row.scope == *scope => *row,
            _ => return Err(ScopeBatchError::FormatMismatch),
        };
        operation.plan(&authority, &checkpoint, |key| {
            decode(&self.physical_key(key))
        })
    }
}
