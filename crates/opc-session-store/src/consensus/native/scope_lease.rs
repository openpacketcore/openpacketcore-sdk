//! Scope operations replace one checkpoint without ordinary receipt history.

use super::*;
use crate::scope_lease::{ScopeLeaseCommand, ScopeLeaseError};

#[cfg(test)]
#[path = "scope_lease_tests.rs"]
mod tests;

pub(super) fn validate_replacement(
    key: &SessionKey,
    before: Option<&NativeKeyState>,
    after: Option<&NativeKeyState>,
) -> io::Result<()> {
    if !crate::scope_lease::is_scope_lease_key(key) {
        return Ok(());
    }
    let Some(old) = before.and_then(|row| row.record.as_ref()) else {
        return Ok(());
    };
    let previous = crate::scope_lease::ScopeLeaseCheckpoint::from_record(old)
        .map_err(|_| invalid("scope checkpoint predecessor invalid"))?;
    let next = after
        .and_then(|row| row.record.as_ref())
        .ok_or_else(|| invalid("scope checkpoint cannot be pruned"))?;
    let next = crate::scope_lease::ScopeLeaseCheckpoint::from_record(next)
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
            .filter(|(key, _)| crate::scope_lease::is_scope_lease_key(key))
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
    pub(super) fn scope_lease(
        &mut self,
        command: &SessionConsensusCommand,
        operation: &ScopeLeaseCommand,
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
            .map(crate::scope_lease::ScopeLeaseCheckpoint::from_record)
            .transpose();
        let result = if scope.store() != self.base.identity.cluster_id() {
            Err(ScopeLeaseError::Unauthorized)
        } else if !authorized {
            Err(crate::sqlite::consensus::scope_lease::authority_error(
                command,
                self.base.identity.configuration_epoch(),
            ))
        } else if !self.scope_profile_active()? {
            Err(ScopeLeaseError::ProfileNotActivated)
        } else if self.request_receipt(&slot).is_some() || current.is_err() {
            // Previous stored profiles cannot be forgotten or migrated.
            Err(ScopeLeaseError::FormatMismatch)
        } else {
            operation.apply(
                current
                    .unwrap()
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
            Ok(SessionMutationOutcome::ScopeLease(result.clone())),
        );
        if let Ok(checkpoint) = result {
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
