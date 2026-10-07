//! Scope operations replace one checkpoint without ordinary receipt history.

use super::*;
use crate::scope_lease::{ScopeLeaseCommand, ScopeLeaseError};

#[cfg(test)]
#[path = "scope_lease_tests.rs"]
mod tests;

#[cfg(test)]
impl NativeState {
    pub(crate) fn scope_checkpoint_footprint_for_test(&self) -> (usize, usize, usize, usize) {
        let bytes = self
            .generic_receipts
            .iter()
            .map(|(id, row)| postcard::to_allocvec(&(id, &**row)).unwrap().len())
            .sum();
        (
            self.generic_receipts.len(),
            bytes,
            self.keys.len(),
            self.notifications.len(),
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
        let (occupied_other, current) = match self.request_receipt(&slot) {
            Some(NativeGenericReceipt::Ordinary(row)) => (
                false,
                Some((row.payload_digest, row.response.as_ref().clone())),
            ),
            Some(_) => (true, None),
            None => (false, None),
        };
        let result = if scope.store() != self.base.identity.cluster_id() {
            Err(ScopeLeaseError::Unauthorized)
        } else if !authorized {
            Err(crate::sqlite::consensus::scope_lease::authority_error(
                command,
                self.base.identity.configuration_epoch(),
            ))
        } else if occupied_other || self.physical_key(&key).record.is_some() {
            // Profile 1 authority cannot be forgotten or silently migrated.
            Err(ScopeLeaseError::FormatMismatch)
        } else {
            operation.apply(current)
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
            self.generic_receipts.insert(
                slot,
                NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
                    payload_digest: checkpoint
                        .digest()
                        .map_err(|_| invalid("scope checkpoint invalid"))?,
                    response: Box::new(response.clone()),
                }),
            );
        }
        Ok(response)
    }
}
