//! Independent management signatures over the already sealed consensus rows.

use super::{AuditKeyRing, AuditKeyTransition};
use crate::audit_authority::ledger::{
    authenticate, verify, EntryPayload, LedgerEntry, LedgerState,
};
use crate::audit_authority::AuditAuthorityError;
use crate::ConfigConsensusIdentity;
use serde::{Deserialize, Serialize};

const ROW_DOMAIN: &[u8] = b"openpacketcore/management-audit/portable-row/v1\0";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedAuditRow {
    pub(crate) epoch: u64,
    pub(crate) previous: [u8; 32],
    pub(crate) signature: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContinuityState {
    pub(crate) version: u16,
    pub(crate) initial_epoch: u64,
    pub(crate) floor_epoch: u64,
    pub(crate) floor_anchor: [u8; 32],
    pub(crate) active_epoch: u64,
    pub(crate) terminal: [u8; 32],
    pub(crate) rows: Vec<SignedAuditRow>,
    pub(crate) checkpoint: Option<super::AuditCheckpoint>,
    pub(crate) export_checkpoint: Option<super::AuditCheckpoint>,
}

impl ContinuityState {
    pub(crate) fn new(epoch: u64) -> Self {
        Self {
            version: 2,
            initial_epoch: epoch,
            floor_epoch: epoch,
            floor_anchor: [0; 32],
            active_epoch: epoch,
            terminal: [0; 32],
            rows: Vec::new(),
            checkpoint: None,
            export_checkpoint: None,
        }
    }
}

pub(crate) fn verify_row(
    keys: &AuditKeyRing,
    identity: ConfigConsensusIdentity,
    epoch: u64,
    previous: [u8; 32],
    entry: &LedgerEntry,
    row: &SignedAuditRow,
) -> Result<u64, AuditAuthorityError> {
    if row.epoch != epoch || row.previous != previous {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    verify(
        keys.key(epoch)?,
        ROW_DOMAIN,
        &(identity, epoch, previous, entry),
        &row.signature,
    )?;
    if let EntryPayload::KeyTransition(transition) = &entry.payload {
        transition.verify(
            keys,
            identity,
            entry
                .sequence
                .checked_sub(1)
                .ok_or(AuditAuthorityError::BindingMismatch)?,
            previous,
            epoch,
        )?;
        Ok(transition.body.to_epoch)
    } else {
        Ok(epoch)
    }
}

impl LedgerState {
    pub(crate) fn validate_continuity(
        &self,
        keys: Option<&AuditKeyRing>,
    ) -> Result<(), AuditAuthorityError> {
        let Some(chain) = &self.continuity else {
            return Ok(());
        };
        let keys = keys.ok_or(AuditAuthorityError::KeyUnavailable)?;
        if chain.version != 2 || chain.rows.len() != self.entries.len() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut epoch = chain.floor_epoch;
        let mut previous = chain.floor_anchor;
        for (entry, row) in self.entries.iter().zip(&chain.rows) {
            epoch = verify_row(keys, self.identity, epoch, previous, entry, row)?;
            previous = row.signature;
        }
        keys.key(epoch)?;
        if epoch != chain.active_epoch || previous != chain.terminal {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if let Some(checkpoint) = &chain.checkpoint {
            checkpoint.verify(keys, self.identity)?;
            self.matches_checkpoint(checkpoint)?;
        }
        if let Some(export) = &chain.export_checkpoint {
            export.verify(keys, self.identity)?;
            self.matches_checkpoint(export)?;
            if export.body.acknowledged_export == [0; 32]
                || chain
                    .checkpoint
                    .as_ref()
                    .is_none_or(|checkpoint| checkpoint.sequence() < export.sequence())
            {
                return Err(AuditAuthorityError::BindingMismatch);
            }
        }
        Ok(())
    }

    pub(crate) fn mutation_outcome_needs_checkpoint(
        &self,
        operation: &crate::audit_authority::ledger::LedgerOperation,
    ) -> bool {
        self.continuity.as_ref().is_some_and(|chain| {
            operation.handle.body.mutation.is_some()
                && operation.state != crate::audit_authority::AuditOperationState::Intent
                && (!operation.terminal_recorded
                    || chain
                        .checkpoint
                        .as_ref()
                        .is_none_or(|checkpoint| checkpoint.sequence() < operation.last_sequence))
        })
    }

    /// Existing rows must be verified before mutation; this appends only missing
    /// signatures inside the same transaction as their underlying ledger rows.
    pub(crate) fn seal_continuity(
        &mut self,
        keys: Option<&AuditKeyRing>,
    ) -> Result<(), AuditAuthorityError> {
        let Some(chain) = &mut self.continuity else {
            return Ok(());
        };
        let keys = keys.ok_or(AuditAuthorityError::KeyUnavailable)?;
        if chain.rows.len() > self.entries.len() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        for entry in &self.entries[chain.rows.len()..] {
            let epoch = chain.active_epoch;
            let previous = chain.terminal;
            let signature = authenticate(
                keys.key(epoch)?,
                ROW_DOMAIN,
                &(self.identity, epoch, previous, entry),
            )?;
            let row = SignedAuditRow {
                epoch,
                previous,
                signature,
            };
            chain.active_epoch = verify_row(keys, self.identity, epoch, previous, entry, &row)?;
            chain.terminal = signature;
            chain.rows.push(row);
        }
        Ok(())
    }

    pub(crate) fn transition_key(
        &mut self,
        root: &crate::AuditKey,
        keys: &AuditKeyRing,
        transition: &AuditKeyTransition,
    ) -> Result<(), AuditAuthorityError> {
        self.validate_continuity(Some(keys))?;
        let chain = self
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        // Exact retry after acknowledged or lost apply is idempotent.
        if self.entries.iter().any(|entry| {
            matches!(&entry.payload,
            EntryPayload::KeyTransition(previous) if **previous == *transition)
        }) {
            return Ok(());
        }
        transition.verify(
            keys,
            self.identity,
            self.sequence,
            chain.terminal,
            chain.active_epoch,
        )?;
        if self.used_capacity()? >= self.limits.max_events {
            return Err(AuditAuthorityError::Full);
        }
        self.append(
            root,
            EntryPayload::KeyTransition(Box::new(transition.clone())),
        )?;
        self.seal_continuity(Some(keys))
    }

    pub(crate) fn prune(
        &mut self,
        keys: &AuditKeyRing,
        through: u64,
        checkpoint: &super::AuditCheckpoint,
        now: i64,
    ) -> Result<(), AuditAuthorityError> {
        self.validate_continuity(Some(keys))?;
        self.matches_checkpoint(checkpoint)?;
        let chain = self
            .continuity
            .as_mut()
            .ok_or(AuditAuthorityError::Unavailable)?;
        if chain.export_checkpoint.as_ref() != Some(checkpoint)
            || checkpoint.body.acknowledged_export == [0; 32]
            || through > checkpoint.body.sequence
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if through < self.floor {
            return Err(AuditAuthorityError::Pruned);
        }
        if through == self.floor {
            return Ok(());
        }
        if self.operations.iter().any(|op| {
            op.first_sequence <= through
                && (!op.terminal_recorded
                    || op.last_sequence > through
                    || now < op.handle.body.expires_at)
        }) {
            return Err(AuditAuthorityError::Full);
        }
        let count =
            usize::try_from(through - self.floor).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let last = self
            .entries
            .get(count - 1)
            .ok_or(AuditAuthorityError::InvalidInput)?;
        let signed = chain
            .rows
            .get(count - 1)
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        chain.floor_epoch = match &last.payload {
            EntryPayload::KeyTransition(t) => t.body.to_epoch,
            _ => signed.epoch,
        };
        chain.floor_anchor = signed.signature;
        self.floor = through;
        self.predecessor = last.mac;
        self.entries.drain(..count);
        chain.rows.drain(..count);
        self.operations.retain(|op| op.first_sequence > through);
        Ok(())
    }
}
