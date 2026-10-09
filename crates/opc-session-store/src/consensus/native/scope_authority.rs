//! Scope operations replace one checkpoint without ordinary receipt history.

use super::*;
use crate::scope_authority::{ScopeAuthorityCommand, ScopeAuthorityError};

#[cfg(test)]
#[path = "scope_authority_tests.rs"]
mod tests;

pub(super) fn validate_replacement(
    key: &SessionKey,
    before: Option<&NativeKeyState>,
    after: Option<&NativeKeyState>,
) -> io::Result<()> {
    if !crate::scope_authority::is_scope_authority_key(key) {
        return Ok(());
    }
    let Some(old) = before.and_then(|row| row.record.as_ref()) else {
        return Ok(());
    };
    let previous = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(old)
        .map_err(|_| invalid("scope checkpoint predecessor invalid"))?;
    let next = after
        .and_then(|row| row.record.as_ref())
        .ok_or_else(|| invalid("scope checkpoint cannot be pruned"))?;
    let next = crate::scope_authority::ScopeAuthorityCheckpoint::from_record(next)
        .map_err(|_| invalid("scope checkpoint successor invalid"))?;
    if !next.can_replace(&previous) {
        return Err(invalid("scope checkpoint floors regressed"));
    }
    Ok(())
}

#[cfg(test)]
impl NativeState {
    pub(crate) fn scope_checkpoint_footprint_for_test(
        &self,
    ) -> (usize, usize, usize, usize, usize) {
        let checkpoints: Vec<_> = self
            .keys
            .iter()
            .filter(|(key, _)| crate::scope_authority::is_scope_authority_key(key))
            .collect();
        let bytes: usize = self
            .keys
            .iter()
            .map(|(key, row)| postcard::to_allocvec(&(key, &**row)).unwrap().len())
            .sum::<usize>()
            + self
                .generic_receipts
                .iter()
                .map(|(id, row)| postcard::to_allocvec(&(id, &**row)).unwrap().len())
                .sum::<usize>();
        (
            checkpoints.len(),
            bytes,
            self.keys
                .iter()
                .filter(|(key, _)| !crate::scope_storage::is_scope_record_key(key))
                .count(),
            self.notifications.len(),
            self.generic_receipts.len(),
        )
    }
}

impl NativeDelta<'_> {
    fn has_scope_rows(&self, scope: &crate::scope_authority::ScopeId) -> io::Result<bool> {
        for key in self
            .base
            .keys
            .iter()
            .map(|(key, _)| key)
            .chain(self.keys.keys())
        {
            if key.tenant != *scope.tenant()
                || key.nf_kind != *scope.nf_kind()
                || !crate::scope_storage::is_scope_record_key(key)
            {
                continue;
            }
            if key.key_type.as_str() == "opc-scope-lease"
                && key.stable_id.as_bytes() == scope.slot()
            {
                return Ok(true);
            }
            if !crate::scope_storage::is_batch_record_key(key) {
                continue;
            }
            let physical = self.physical_key(key);
            let Some(record) = physical.record.as_ref() else {
                return Err(invalid("scope orphan row has no record"));
            };
            let row = crate::scope_storage::ScopeRow::from_record(record)
                .map_err(|_| invalid("scope orphan row invalid"))?;
            if row.scope() == Some(scope) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) fn scope_authority(
        &mut self,
        command: &SessionConsensusCommand,
        operation: &ScopeAuthorityCommand,
        authorized: bool,
        now: Timestamp,
        index: u64,
    ) -> io::Result<SessionConsensusResponse> {
        let scope = operation.request.scope();
        let slot = scope
            .checkpoint_id()
            .map_err(|_| invalid("scope key invalid"))?;
        let key = scope.key().map_err(|_| invalid("scope key invalid"))?;
        let row = self.physical_key(&key);
        let current = row
            .record
            .as_ref()
            .map(crate::scope_authority::ScopeAuthorityCheckpoint::from_record)
            .transpose();
        let initialize_ledger = current.as_ref().is_ok_and(|value| value.is_none());
        let result = if scope.store() != self.base.identity.cluster_id() {
            Err(ScopeAuthorityError::Unauthorized)
        } else if !authorized {
            Err(crate::sqlite::consensus::scope_authority::authority_error(
                command,
                self.base.identity.configuration_epoch(),
            ))
        } else if !self.scope_profile_active()? {
            Err(ScopeAuthorityError::ProfileNotActivated)
        } else if self.request_receipt(&slot).is_some() || current.is_err() {
            // Previous stored profiles cannot be forgotten or migrated.
            Err(ScopeAuthorityError::FormatMismatch)
        } else if current.as_ref().is_ok_and(|value| value.is_none())
            && self.has_scope_rows(scope)?
        {
            // No authority row is not proof of an unused domain. Orphaned
            // children, claims and stable floors must never be adopted/reset.
            Err(ScopeAuthorityError::FormatMismatch)
        } else {
            operation.apply(
                current
                    .map_err(|_| invalid("scope checkpoint invalid"))?
                    .map(|checkpoint| checkpoint.stored())
                    .transpose()
                    .map_err(|_| invalid("scope checkpoint invalid"))?,
            )
        };
        let sequence = self
            .frontiers
            .sequence
            .checked_add(1)
            .filter(|value| *value <= COUNTER_MAX)
            .ok_or_else(|| invalid("scope application sequence exhausted"))?;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("scope command digest invalid"))?;
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        let response = self.response(
            index,
            Ok(SessionMutationOutcome::ScopeAuthority(result.clone())),
        );
        if let Ok(checkpoint) = result {
            if initialize_ledger {
                let ledger = crate::scope_storage::ScopeRow::Batch(Box::new(
                    crate::scope_batch::ScopeBatchCheckpoint::empty(scope.clone()),
                ))
                .to_record()
                .map_err(|_| invalid("scope initial ledger invalid"))?;
                self.keys.insert(
                    ledger.key.clone(),
                    NativeKeyState {
                        record: Some(ledger),
                        ..NativeKeyState::default()
                    },
                );
            }
            self.keys.insert(
                key,
                NativeKeyState {
                    record: Some(
                        checkpoint
                            .to_record()
                            .map_err(|_| invalid("scope checkpoint invalid"))?,
                    ),
                    ..NativeKeyState::default()
                },
            );
        }
        Ok(response)
    }
}
