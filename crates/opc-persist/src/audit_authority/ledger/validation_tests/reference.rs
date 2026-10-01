//! Frozen pre-index validator from 78aa9794d1b1af41a1bcf2ec991ea58d3d011279; only comparison counters added.
//! New payload variants are outside this legacy fixture oracle; its original
//! match arms and comparison counters remain unchanged.
//! Original ledger SHA-256: d8dd869cdf04d0da944842189b8cc5bf9b14f2c2fd4d4c9f73245e7cf2c7ecbb.

use super::*;

pub(super) fn validate(
    ledger: &LedgerState,
    key: &AuditKey,
    identity: ConfigConsensusIdentity,
) -> Result<(), AuditAuthorityError> {
    ledger.limits.validate()?;
    if ledger.version != 1
        || ledger.identity != identity
        || ledger.operations.len() > ledger.limits.max_operations
        || ledger.used_capacity()? > ledger.limits.max_events
        || ledger.entries.len() > ledger.limits.max_events
    {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    let mut sequence = ledger.floor;
    let mut previous = ledger.predecessor;
    let mut derived: Vec<LedgerOperation> = Vec::new();
    for entry in &ledger.entries {
        sequence = sequence
            .checked_add(1)
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        if entry.sequence != sequence
            || entry.previous != previous
            || entry.key_epoch != key.epoch()
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(
            key,
            ENTRY_DOMAIN,
            &(
                ledger.identity,
                sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
            &entry.mac,
        )?;
        match &entry.payload {
            EntryPayload::Intent(handle) => {
                handle.verify(key, identity, handle.body.binding.caller)?;
                if handle.body.event.projection != ledger.projection
                    || derived.iter().any(|op| {
                        validation_probe::comparison();
                        op.handle.body.binding.request == handle.body.binding.request
                    })
                {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                let intent = handle.body.event.outcome == crate::ManagementAuditOutcomeCode::Intent;
                derived.push(LedgerOperation {
                    handle: (**handle).clone(),
                    state: if intent {
                        AuditOperationState::Intent
                    } else {
                        AuditOperationState::Observed {
                            outcome: handle.body.event.outcome,
                        }
                    },
                    terminal_recorded: !intent,
                    first_sequence: sequence,
                    last_sequence: sequence,
                    reserved: if intent { 2 } else { 0 },
                });
            }
            EntryPayload::TargetIntent(_) | EntryPayload::EmptyCommit(_) => {
                unreachable!("the frozen pre-index reference only accepts legacy fixtures")
            }
            EntryPayload::Outcome { operation, state } => {
                let op = derived
                    .iter_mut()
                    .find(|op| {
                        validation_probe::comparison();
                        op.handle.mac == *operation
                    })
                    .ok_or(AuditAuthorityError::BindingMismatch)?;
                if op.state != AuditOperationState::Intent
                    || !matches!(
                        state,
                        AuditOperationState::Committed { .. } | AuditOperationState::Rejected
                    )
                {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                op.state = *state;
                op.last_sequence = sequence;
                op.reserved = 1;
            }
            EntryPayload::Terminal { operation } => {
                let op = derived
                    .iter_mut()
                    .find(|op| {
                        validation_probe::comparison();
                        op.handle.mac == *operation
                    })
                    .ok_or(AuditAuthorityError::BindingMismatch)?;
                if op.state == AuditOperationState::Intent || op.terminal_recorded {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                op.terminal_recorded = true;
                op.last_sequence = sequence;
                op.reserved = 0;
            }
            EntryPayload::KeyTransition(_) => {
                if ledger.continuity.is_none() {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
            }
            EntryPayload::Event(event) => {
                if event.projection != ledger.projection {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
            }
        }
        previous = entry.mac;
    }
    if derived != ledger.operations {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    if sequence != ledger.sequence || previous != ledger.terminal {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    for (index, op) in ledger.operations.iter().enumerate() {
        op.handle
            .verify(key, identity, op.handle.body.binding.caller)?;
        let reserved = match (op.state, op.terminal_recorded) {
            (AuditOperationState::Intent, false) => 2,
            (AuditOperationState::Intent, true) => {
                return Err(AuditAuthorityError::BindingMismatch)
            }
            (_, false) => 1,
            (_, true) => 0,
        };
        if op.reserved != reserved
            || op.first_sequence <= ledger.floor
            || op.last_sequence > ledger.sequence
            || op.last_sequence < op.first_sequence
            || ledger.operations[..index].iter().any(|other| {
                validation_probe::comparison();
                other.handle.body.binding.request == op.handle.body.binding.request
            })
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
    }
    Ok(())
}
