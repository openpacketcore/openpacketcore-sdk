//! Deterministic bounded state used only by the configuration consensus owner.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::{
    AuditAuthorityError, AuditCaller, AuditOperationBinding, AuditToken, ProjectedAuditEvent,
};
use crate::{AuditKey, ConfigConsensusIdentity};

const HANDLE_DOMAIN: &[u8] = b"openpacketcore/management-audit/operation-handle/v1\0";
const ENTRY_DOMAIN: &[u8] = b"openpacketcore/management-audit/replicated-entry/v1\0";
pub(crate) const STATE_DOMAIN: &[u8] = b"openpacketcore/management-audit/replicated-state/v1\0";
pub(crate) const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HANDLE_BYTES: usize = 8192;
const OPERATION_EVENT_RESERVATION: usize = 3;

/// Fixed capacity admitted with the ledger, including reserved outcome slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLedgerLimits {
    pub(crate) max_events: usize,
    pub(crate) max_operations: usize,
}

impl AuditLedgerLimits {
    /// Admit 3..4096 events and 1..1024 retained operations.
    /// Each operation reserves an intent, authoritative outcome, and terminal
    /// acknowledgement. Unresolved operations retain all unused reservations.
    pub fn new(max_events: usize, max_operations: usize) -> Result<Self, AuditAuthorityError> {
        let limits = Self {
            max_events,
            max_operations,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), AuditAuthorityError> {
        if !(3..=4096).contains(&self.max_events)
            || !(1..=1024).contains(&self.max_operations)
            || self.max_operations > self.max_events / OPERATION_EVENT_RESERVATION
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HandleBody {
    pub(crate) version: u16,
    pub(crate) identity: ConfigConsensusIdentity,
    pub(crate) binding: AuditOperationBinding,
    pub(crate) event: ProjectedAuditEvent,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) nonce: [u8; 16],
    pub(crate) key_epoch: u64,
    pub(crate) mutation: Option<[u8; 32]>,
}

/// Authenticated recovery handle; preparation alone grants no mutation authority.
///
/// Persist this handle before awaiting admission. Cancellation or acknowledgement
/// loss requires an authorized lookup of this exact handle, never a newly minted
/// request. The fixed expiry cannot be extended by retries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOperationHandle {
    pub(crate) body: HandleBody,
    pub(crate) mac: [u8; 32],
}

impl fmt::Debug for AuditOperationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuditOperationHandle(<redacted>)")
    }
}

impl AuditOperationHandle {
    /// Encode for opaque protected client recovery storage. Not a diagnostic value.
    pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
        let bytes = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.len() > MAX_HANDLE_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        Ok(bytes)
    }

    /// Decode a bounded untrusted token. Only an authority lookup validates it.
    pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
        if bytes.len() > MAX_HANDLE_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)
    }

    pub(crate) fn issue(body: HandleBody, key: &AuditKey) -> Result<Self, AuditAuthorityError> {
        if body.version != 1
            || body.key_epoch != key.epoch()
            || body.binding.caller != body.event.caller
            || body.binding.request != body.event.request
            || (body.event.outcome != crate::ManagementAuditOutcomeCode::Intent
                && body.mutation.is_some())
            || body
                .expires_at
                .checked_sub(body.issued_at)
                .is_none_or(|age| !(1..=3600).contains(&age))
        {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let mac = authenticate(key, HANDLE_DOMAIN, &body)?;
        Ok(Self { body, mac })
    }

    pub(crate) fn verify(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        if self.body.version != 1
            || self.body.identity != identity
            || self.body.key_epoch != key.epoch()
            || self.body.binding.caller != caller
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(key, HANDLE_DOMAIN, &self.body, &self.mac)
    }

    pub(crate) fn require_live(&self, now: i64) -> Result<(), AuditAuthorityError> {
        if now < self.body.issued_at || now >= self.body.expires_at {
            return Err(AuditAuthorityError::Expired);
        }
        Ok(())
    }
}

/// Durable state, not an inference from a response timeout or missing row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditOperationState {
    /// Intent committed; no authoritative configuration outcome recorded yet.
    Intent,
    /// Configuration mutation and this result were applied atomically.
    Committed {
        /// Authoritative configuration revision. No transaction identity is exposed.
        version: u64,
    },
    /// The authority closed the intent without applying its configuration mutation.
    Rejected,
    /// Standalone observation, without an associated configuration mutation.
    Observed {
        /// Source outcome, independent of configuration authority.
        outcome: crate::ManagementAuditOutcomeCode,
    },
    /// Retained target/lifecycle effect with its complete resulting state anchor.
    /// This is disjoint from a running-only committed revision.
    TargetV1(super::NetconfTargetResult),
}

impl AuditOperationState {
    pub(crate) fn validate_target_for(
        self,
        handle: &AuditOperationHandle,
    ) -> Result<(), AuditAuthorityError> {
        if let Self::TargetV1(result) = self {
            result.validate_for(handle)?;
        }
        Ok(())
    }
}

/// Authenticated operation result from a quorum-applied response or quorum read.
/// A response proves its point-in-time outcome; use authorized lookup for the
/// current terminal-record status. A later outage cannot erase a known commit.
#[derive(Clone, PartialEq, Eq)]
pub struct AuditOperationReceipt {
    pub(crate) handle: AuditOperationHandle,
    pub(crate) state: AuditOperationState,
    pub(crate) terminal_recorded: bool,
    pub(crate) sequence: u64,
}

impl AuditOperationReceipt {
    /// Read the authoritative mutation outcome.
    pub const fn state(&self) -> AuditOperationState {
        self.state
    }
    /// Whether the reserved terminal obligation is durably fulfilled.
    pub const fn terminal_recorded(&self) -> bool {
        self.terminal_recorded
    }
    /// Opaque identity to retain for another authorized lookup.
    pub fn handle(&self) -> &AuditOperationHandle {
        &self.handle
    }
}

impl fmt::Debug for AuditOperationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditOperationReceipt")
            .field("state", &self.state)
            .field("terminal_recorded", &self.terminal_recorded)
            .finish_non_exhaustive()
    }
}

/// Separates definite pre-admission rejection from possibly admitted work.
#[derive(Debug)]
pub enum AuditAdmission {
    /// No mutation was admitted by this call.
    Rejected(AuditAuthorityError),
    /// Work may have been admitted; lookup is required and mutation is forbidden.
    Unknown(AuditOperationHandle),
    /// The exact operation was durably admitted and read back.
    Applied(AuditOperationReceipt),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerOperation {
    pub(crate) handle: AuditOperationHandle,
    pub(crate) state: AuditOperationState,
    pub(crate) terminal_recorded: bool,
    pub(crate) first_sequence: u64,
    pub(crate) last_sequence: u64,
    pub(crate) reserved: usize,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EntryPayload {
    Event(Box<ProjectedAuditEvent>),
    KeyTransition(Box<super::continuity::AuditKeyTransition>),
    Intent(Box<AuditOperationHandle>),
    Outcome {
        operation: [u8; 32],
        state: AuditOperationState,
    },
    Terminal {
        operation: [u8; 32],
    },
    // Append-only allocation. Both the ordinary root chain and the independent
    // continuity chain authenticate the exact closed recovery description.
    TargetIntent(Box<RetainedTargetIntent>),
}

// Scope strict decoding to the new format. Existing payload decoding and all
// serialized field order/bytes remain unchanged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedTargetIntent {
    #[serde(deserialize_with = "deserialize_target_handle")]
    pub(crate) handle: AuditOperationHandle,
    pub(crate) recovery: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerEntry {
    pub(crate) sequence: u64,
    pub(crate) previous: [u8; 32],
    pub(crate) payload: EntryPayload,
    pub(crate) key_epoch: u64,
    pub(crate) mac: [u8; 32],
}

/// Exactly one bounded state, changed inside the existing Raft apply transaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerState {
    pub(crate) version: u16,
    pub(crate) identity: ConfigConsensusIdentity,
    pub(crate) projection: AuditToken,
    pub(crate) limits: AuditLedgerLimits,
    pub(crate) sequence: u64,
    pub(crate) terminal: [u8; 32],
    pub(crate) floor: u64,
    pub(crate) predecessor: [u8; 32],
    pub(crate) entries: Vec<LedgerEntry>,
    pub(crate) operations: Vec<LedgerOperation>,
    pub(crate) continuity: Option<super::continuity::chain::ContinuityState>,
}

impl LedgerState {
    pub(crate) fn new(
        identity: ConfigConsensusIdentity,
        projection: AuditToken,
        limits: AuditLedgerLimits,
    ) -> Self {
        Self {
            version: 1,
            identity,
            projection,
            limits,
            sequence: 0,
            terminal: [0; 32],
            floor: 0,
            predecessor: [0; 32],
            entries: Vec::new(),
            operations: Vec::new(),
            continuity: None,
        }
    }

    pub(crate) fn used_capacity(&self) -> Result<usize, AuditAuthorityError> {
        self.operations
            .iter()
            .try_fold(self.entries.len(), |used, op| {
                used.checked_add(op.reserved)
                    .ok_or(AuditAuthorityError::Full)
            })
    }

    pub(crate) fn append(
        &mut self,
        key: &AuditKey,
        payload: EntryPayload,
    ) -> Result<u64, AuditAuthorityError> {
        let next = self
            .sequence
            .checked_add(1)
            .filter(|seq| *seq <= i64::MAX as u64)
            .ok_or(AuditAuthorityError::Full)?;
        if self.entries.len() >= self.limits.max_events {
            return Err(AuditAuthorityError::Full);
        }
        let mac = authenticate(
            key,
            ENTRY_DOMAIN,
            &(self.identity, next, self.terminal, key.epoch(), &payload),
        )?;
        self.entries.push(LedgerEntry {
            sequence: next,
            previous: self.terminal,
            payload,
            key_epoch: key.epoch(),
            mac,
        });
        self.sequence = next;
        self.terminal = mac;
        Ok(next)
    }

    pub(crate) fn admit(
        &mut self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        now: i64,
    ) -> Result<(), AuditAuthorityError> {
        self.admit_with_recovery(key, handle, now, None)
    }

    pub(crate) fn admit_target(
        &mut self,
        key: &AuditKey,
        prepared: &super::PreparedTargetMutation,
        now: i64,
    ) -> Result<(), AuditAuthorityError> {
        if self.continuity.is_none() {
            return Err(AuditAuthorityError::RecoveryRequired);
        }
        prepared.verify_effect(key)?;
        let recovery =
            String::from_utf8(prepared.encode()?).map_err(|_| AuditAuthorityError::InvalidInput)?;
        self.admit_with_recovery(key, prepared.handle(), now, Some(recovery))
    }

    fn admit_with_recovery(
        &mut self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        now: i64,
        recovery: Option<String>,
    ) -> Result<(), AuditAuthorityError> {
        // Failed admission leaves the in-memory candidate unchanged as well as
        // the outer transaction. Existing legacy-only admission keeps its path.
        if recovery.is_some() || self.has_target_intents() {
            let mut candidate = self.clone();
            candidate.admit_inner(key, handle, now, recovery)?;
            candidate.check_target_capacity()?;
            *self = candidate;
            Ok(())
        } else {
            self.admit_inner(key, handle, now, recovery)
        }
    }

    fn admit_inner(
        &mut self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        now: i64,
        recovery: Option<String>,
    ) -> Result<(), AuditAuthorityError> {
        handle.verify(key, self.identity, handle.body.binding.caller)?;
        if let Some(existing) = self
            .operations
            .iter()
            .find(|op| op.handle.body.binding.request == handle.body.binding.request)
        {
            let previous = self.entries.iter().find_map(|entry| {
                if entry.sequence != existing.first_sequence {
                    return None;
                }
                match &entry.payload {
                    EntryPayload::Intent(_) => Some(None),
                    EntryPayload::TargetIntent(retained) => Some(Some(&retained.recovery)),
                    _ => None,
                }
            });
            return if existing.handle == *handle && previous == Some(recovery.as_ref()) {
                Ok(())
            } else {
                Err(AuditAuthorityError::BindingMismatch)
            };
        }
        handle.require_live(now)?;
        if handle.body.mutation.is_some()
            && self
                .operations
                .iter()
                .any(|operation| self.mutation_outcome_needs_checkpoint(operation))
        {
            return Err(AuditAuthorityError::RecoveryRequired);
        }
        if handle.body.event.projection != self.projection {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let is_intent = handle.body.event.outcome == crate::ManagementAuditOutcomeCode::Intent;
        let reservation = if is_intent {
            OPERATION_EVENT_RESERVATION
        } else {
            1
        };
        if self.operations.len() >= self.limits.max_operations
            || self
                .used_capacity()?
                .checked_add(reservation)
                .is_none_or(|used| used > self.limits.max_events)
        {
            return Err(AuditAuthorityError::Full);
        }
        let handle_payload = Box::new(handle.clone());
        let payload = match recovery {
            Some(recovery) => EntryPayload::TargetIntent(Box::new(RetainedTargetIntent {
                handle: *handle_payload,
                recovery,
            })),
            None => EntryPayload::Intent(handle_payload),
        };
        let sequence = self.append(key, payload)?;
        self.operations.push(LedgerOperation {
            handle: handle.clone(),
            state: if is_intent {
                AuditOperationState::Intent
            } else {
                AuditOperationState::Observed {
                    outcome: handle.body.event.outcome,
                }
            },
            terminal_recorded: !is_intent,
            first_sequence: sequence,
            last_sequence: sequence,
            reserved: reservation - 1,
        });
        Ok(())
    }

    fn has_target_intents(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.payload, EntryPayload::TargetIntent(_)))
    }

    // The existing 16 MiB aggregate is unchanged. Reserve a conservative 32 KiB
    // for each remaining fixed-shape outcome/terminal event, including its
    // operation-index update and both chain authenticators. No future outcome
    // contains configuration/envelope bytes or variable-length caller strings.
    // Additional fixed slack covers the stored wrapper and two checkpoints;
    // unsealed rows retain space for their independent chain authenticator.
    pub(crate) fn check_target_capacity(&self) -> Result<(), AuditAuthorityError> {
        if !self.has_target_intents() {
            return Ok(());
        }
        let reserved = self.operations.iter().try_fold(0usize, |used, op| {
            used.checked_add(op.reserved)
                .ok_or(AuditAuthorityError::Full)
        })?;
        let unsealed = self
            .continuity
            .as_ref()
            .map_or(self.entries.len(), |chain| {
                self.entries.len().saturating_sub(chain.rows.len())
            });
        let encoded = serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let required = reserved
            .checked_mul(32 * 1024)
            .and_then(|n| {
                unsealed
                    .checked_mul(1024)
                    .and_then(|rows| n.checked_add(rows))
            })
            .and_then(|n| n.checked_add(16 * 1024))
            .and_then(|n| n.checked_add(encoded.len()))
            .ok_or(AuditAuthorityError::Full)?;
        if required > MAX_STATE_BYTES {
            return Err(AuditAuthorityError::Full);
        }
        Ok(())
    }

    pub(crate) fn recover_target(
        &self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<super::PreparedTargetMutation, AuditAuthorityError> {
        handle.verify(key, self.identity, caller)?;
        let index = self.operation_index(key, handle)?;
        let operation = &self.operations[index];
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.sequence == operation.first_sequence)
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        match &entry.payload {
            EntryPayload::TargetIntent(retained) if retained.handle == *handle => {
                validate_target_recovery(key, handle, &retained.recovery)
            }
            _ => Err(AuditAuthorityError::BindingMismatch),
        }
    }

    #[cfg(test)]
    pub(crate) fn append_event(
        &mut self,
        key: &AuditKey,
        event: ProjectedAuditEvent,
    ) -> Result<(), AuditAuthorityError> {
        if event.projection != self.projection {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if self.used_capacity()? >= self.limits.max_events {
            return Err(AuditAuthorityError::Full);
        }
        self.append(key, EntryPayload::Event(Box::new(event)))?;
        Ok(())
    }

    pub(crate) fn resolve(
        &mut self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        state: AuditOperationState,
    ) -> Result<(), AuditAuthorityError> {
        let index = self.operation_index(key, handle)?;
        state.validate_target_for(handle)?;
        let current = &self.operations[index];
        if current.state == state {
            return Ok(());
        }
        if current.state != AuditOperationState::Intent || state == AuditOperationState::Intent {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let sequence = self.append(
            key,
            EntryPayload::Outcome {
                operation: handle.mac,
                state,
            },
        )?;
        let current = &mut self.operations[index];
        current.state = state;
        current.last_sequence = sequence;
        current.reserved = 1;
        Ok(())
    }

    pub(crate) fn acknowledge_terminal(
        &mut self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
    ) -> Result<(), AuditAuthorityError> {
        let index = self.operation_index(key, handle)?;
        let current = &self.operations[index];
        if current.terminal_recorded {
            return Ok(());
        }
        if current.state == AuditOperationState::Intent {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let sequence = self.append(
            key,
            EntryPayload::Terminal {
                operation: handle.mac,
            },
        )?;
        let current = &mut self.operations[index];
        current.terminal_recorded = true;
        current.last_sequence = sequence;
        current.reserved = 0;
        Ok(())
    }

    fn operation_index(
        &self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
    ) -> Result<usize, AuditAuthorityError> {
        handle.verify(key, self.identity, handle.body.binding.caller)?;
        self.operations
            .iter()
            .position(|op| op.handle == *handle)
            .ok_or(AuditAuthorityError::BindingMismatch)
    }

    pub(crate) fn lookup(
        &self,
        key: &AuditKey,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<Option<AuditOperationReceipt>, AuditAuthorityError> {
        handle.verify(key, self.identity, caller)?;
        Ok(self
            .operations
            .iter()
            .find(|op| op.handle == *handle)
            .map(|op| AuditOperationReceipt {
                handle: handle.clone(),
                state: op.state,
                terminal_recorded: op.terminal_recorded,
                sequence: op.last_sequence,
            }))
    }

    pub(crate) fn validate(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
    ) -> Result<(), AuditAuthorityError> {
        self.limits.validate()?;
        if self.version != 1
            || self.identity != identity
            || self.operations.len() > self.limits.max_operations
            || self.used_capacity()? > self.limits.max_events
            || self.entries.len() > self.limits.max_events
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut sequence = self.floor;
        let mut previous = self.predecessor;
        let mut derived: Vec<LedgerOperation> = Vec::new();
        for entry in &self.entries {
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
                    self.identity,
                    sequence,
                    previous,
                    entry.key_epoch,
                    &entry.payload,
                ),
                &entry.mac,
            )?;
            let intent_handle = match &entry.payload {
                EntryPayload::Intent(handle) => Some(&**handle),
                EntryPayload::TargetIntent(retained) => {
                    if self.continuity.is_none() {
                        return Err(AuditAuthorityError::BindingMismatch);
                    }
                    validate_target_recovery(key, &retained.handle, &retained.recovery)?;
                    Some(&retained.handle)
                }
                _ => None,
            };
            if let Some(handle) = intent_handle {
                handle.verify(key, identity, handle.body.binding.caller)?;
                if handle.body.event.projection != self.projection
                    || derived
                        .iter()
                        .any(|op| op.handle.body.binding.request == handle.body.binding.request)
                {
                    return Err(AuditAuthorityError::BindingMismatch);
                }
                let intent = handle.body.event.outcome == crate::ManagementAuditOutcomeCode::Intent;
                derived.push(LedgerOperation {
                    handle: handle.clone(),
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
            match &entry.payload {
                EntryPayload::Intent(_) | EntryPayload::TargetIntent(_) => {}
                EntryPayload::Outcome { operation, state } => {
                    let op = derived
                        .iter_mut()
                        .find(|op| op.handle.mac == *operation)
                        .ok_or(AuditAuthorityError::BindingMismatch)?;
                    if op.state != AuditOperationState::Intent
                        || !matches!(
                            state,
                            AuditOperationState::Committed { .. }
                                | AuditOperationState::Rejected
                                | AuditOperationState::TargetV1(_)
                        )
                    {
                        return Err(AuditAuthorityError::BindingMismatch);
                    }
                    state.validate_target_for(&op.handle)?;
                    op.state = *state;
                    op.last_sequence = sequence;
                    op.reserved = 1;
                }
                EntryPayload::Terminal { operation } => {
                    let op = derived
                        .iter_mut()
                        .find(|op| op.handle.mac == *operation)
                        .ok_or(AuditAuthorityError::BindingMismatch)?;
                    if op.state == AuditOperationState::Intent || op.terminal_recorded {
                        return Err(AuditAuthorityError::BindingMismatch);
                    }
                    op.terminal_recorded = true;
                    op.last_sequence = sequence;
                    op.reserved = 0;
                }
                EntryPayload::KeyTransition(_) => {
                    if self.continuity.is_none() {
                        return Err(AuditAuthorityError::BindingMismatch);
                    }
                }
                EntryPayload::Event(event) => {
                    if event.projection != self.projection {
                        return Err(AuditAuthorityError::BindingMismatch);
                    }
                }
            }
            previous = entry.mac;
        }
        if derived != self.operations {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        if sequence != self.sequence || previous != self.terminal {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.check_target_capacity()?;
        for (index, op) in self.operations.iter().enumerate() {
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
                || op.first_sequence <= self.floor
                || op.last_sequence > self.sequence
                || op.last_sequence < op.first_sequence
                || self.operations[..index].iter().any(|other| {
                    other.handle.body.binding.request == op.handle.body.binding.request
                })
            {
                return Err(AuditAuthorityError::BindingMismatch);
            }
        }
        Ok(())
    }
}

// The target format has strict nested input without changing the legacy handle,
// event, caller or authority codecs (or their authentication byte domains).
pub(crate) fn deserialize_target_handle<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<AuditOperationHandle, D::Error> {
    strict_target_handle::Handle::deserialize(deserializer)
}

mod strict_target_handle {
    use super::*;
    use crate::{
        ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTransportCode,
    };

    #[derive(Deserialize)]
    #[serde(remote = "AuditOperationHandle", deny_unknown_fields)]
    pub(super) struct Handle {
        #[serde(with = "Body")]
        body: HandleBody,
        mac: [u8; 32],
    }

    #[derive(Deserialize)]
    #[serde(remote = "HandleBody", deny_unknown_fields)]
    struct Body {
        version: u16,
        #[serde(with = "crate::audit_authority::target_identity")]
        identity: ConfigConsensusIdentity,
        #[serde(with = "Binding")]
        binding: AuditOperationBinding,
        #[serde(with = "Event")]
        event: ProjectedAuditEvent,
        issued_at: i64,
        expires_at: i64,
        nonce: [u8; 16],
        key_epoch: u64,
        mutation: Option<[u8; 32]>,
    }

    #[derive(Deserialize)]
    #[serde(remote = "AuditOperationBinding", deny_unknown_fields)]
    struct Binding {
        #[serde(with = "crate::audit_authority::target_caller")]
        caller: AuditCaller,
        request: AuditToken,
        operation: AuditToken,
        base_version: u64,
    }

    #[derive(Deserialize)]
    #[serde(remote = "ProjectedAuditEvent", deny_unknown_fields)]
    struct Event {
        projection: AuditToken,
        #[serde(with = "crate::audit_authority::target_caller")]
        caller: AuditCaller,
        request: AuditToken,
        transaction: Option<AuditToken>,
        paths: AuditToken,
        reason: Option<AuditToken>,
        transport: ManagementAuditTransportCode,
        operation: ManagementAuditOperationCode,
        outcome: ManagementAuditOutcomeCode,
        utc_seconds: i64,
        nanosecond: u32,
    }
}

fn validate_target_recovery(
    key: &AuditKey,
    handle: &AuditOperationHandle,
    recovery: &str,
) -> Result<super::PreparedTargetMutation, AuditAuthorityError> {
    let prepared = super::PreparedTargetMutation::decode(recovery.as_bytes())?;
    if prepared.handle() != handle || prepared.encode()?.as_slice() != recovery.as_bytes() {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    prepared.verify_effect(key)?;
    Ok(prepared)
}

pub(crate) fn authenticate<T: Serialize>(
    key: &AuditKey,
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], AuditAuthorityError> {
    Ok(authenticator(key, domain, value)?
        .finalize()
        .into_bytes()
        .into())
}

pub(crate) fn verify<T: Serialize>(
    key: &AuditKey,
    domain: &[u8],
    value: &T,
    expected: &[u8; 32],
) -> Result<(), AuditAuthorityError> {
    authenticator(key, domain, value)?
        .verify_slice(expected)
        .map_err(|_| AuditAuthorityError::BindingMismatch)
}

fn authenticator<T: Serialize>(
    key: &AuditKey,
    domain: &[u8],
    value: &T,
) -> Result<Hmac<Sha256>, AuditAuthorityError> {
    let encoded = serde_json::to_vec(value).map_err(|_| AuditAuthorityError::InvalidInput)?;
    if encoded.len() > MAX_STATE_BYTES {
        return Err(AuditAuthorityError::InvalidInput);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| AuditAuthorityError::KeyUnavailable)?;
    mac.update(domain);
    mac.update(&(encoded.len() as u64).to_be_bytes());
    mac.update(&encoded);
    Ok(mac)
}
