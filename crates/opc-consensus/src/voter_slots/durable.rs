use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::*;
use crate::ConsensusNodeId;

const HEADER: &[u8; 6] = b"OPVG\0\x01";
const MAX_STATE_BYTES: usize = 2 * MAX_VOTER_SLOT_TABLE_BYTES;

/// One effective uncommitted Prepare, persisted atomically with its actual log row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterSlotIntent {
    /// Actual engine-assigned full log identity, never a guessed next index.
    pub log_id: VoterSlotLogId,
    /// Canonical claims selected by the authenticated leader's control boundary.
    pub request: VoterReplacementRequest,
}

impl VoterSlotIntent {
    /// The predecessor being provisionally closed; a pending candidate may be superseded.
    pub fn target(&self) -> ConsensusNodeId {
        VoterSlotIdentity::new(
            self.request.attestation.slot,
            self.request.attestation.expected_incarnation,
        )
        .node_id()
    }
}

/// Bounded, transaction-owned committed table and provisional retirement intent.
///
/// Stores update this record in the same strict transaction as append,
/// truncation, apply or snapshot publication. Transient pre-dispatch attempts
/// belong to runtime admission and are deliberately not inferred from this
/// record. A caller timeout is never an input to durable reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterSlotDurableState {
    table: VoterSlotTable,
    intent: Option<VoterSlotIntent>,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    table: Vec<u8>,
    intent: Option<VoterSlotIntent>,
}

impl VoterSlotDurableState {
    /// Bind a validated initial table. Enrollment and storage freshness are store obligations.
    pub fn new(table: VoterSlotTable) -> Result<Self, VoterSlotError> {
        table.validate()?;
        Ok(Self {
            table,
            intent: None,
        })
    }

    /// Reconstruct separately persisted committed and provisional publications.
    /// The store must verify that the intent names its exact retained, unapplied
    /// Begin entry. A now-stale CAS cannot release that entry's existing fence.
    pub fn restore(
        table: VoterSlotTable,
        intent: Option<VoterSlotIntent>,
    ) -> Result<Self, VoterSlotError> {
        table.validate()?;
        let state = Self { table, intent };
        state.validate_intent()?;
        Ok(state)
    }

    /// Current committed table; it is independent of effective engine membership.
    pub fn table(&self) -> &VoterSlotTable {
        &self.table
    }

    /// Exact provisional log intent, when one has been durably appended.
    pub fn intent(&self) -> Option<&VoterSlotIntent> {
        self.intent.as_ref()
    }

    /// Admit at most one effective intent before acknowledging its durable log append.
    ///
    /// The store must have closed and drained the target's runtime admission and
    /// received the serialized engine fence acknowledgement before this call.
    pub fn append_intent(&mut self, intent: VoterSlotIntent) -> Result<(), VoterReplacementError> {
        self.append_intent_after_prefix(intent, &self.table.clone())
    }

    /// Append against the store's checked projection of its actual preceding log.
    /// The projection grants no committed authority and is never published here.
    /// It handles an append arriving before earlier committed controls apply.
    pub fn append_intent_after_prefix(
        &mut self,
        intent: VoterSlotIntent,
        prefix: &VoterSlotTable,
    ) -> Result<(), VoterReplacementError> {
        prefix
            .validate_successor_of(&self.table)
            .map_err(|_| VoterReplacementError::InvalidTransition)?;
        if let Some(existing) = &self.intent {
            return if existing == &intent {
                Ok(())
            } else {
                Err(VoterReplacementError::ReplacementInProgress)
            };
        }
        let mut proposed = prefix.clone();
        proposed.apply_control(
            &VoterSlotControl::Begin(Box::new(intent.request.clone())),
            intent.log_id,
        )?;
        // A retained exact retry is not another retirement or an uncommitted reservation.
        if &proposed != prefix {
            self.intent = Some(intent);
        }
        Ok(())
    }

    /// Reconcile only after Openraft durably truncates this index and its suffix.
    pub fn truncate_from(&mut self, first_index: u64) {
        if self
            .intent
            .as_ref()
            .is_some_and(|intent| intent.log_id.index >= first_index)
        {
            self.intent = None;
        }
    }

    /// Publish deterministic apply, including a proven no-effect CAS result.
    ///
    /// Advancing application past an intent proves that it cannot later commit
    /// differently. A successful retirement remains in the permanent table.
    pub fn publish_applied(
        &mut self,
        table: VoterSlotTable,
        applied: VoterSlotLogId,
    ) -> Result<(), VoterSlotError> {
        self.publish(table, applied)
    }

    /// Publish a verified committed snapshot in the same transaction as engine state.
    ///
    /// Below the intent index it cannot erase the intent. At or above that index
    /// the retained reservation/floor keeps retirement permanent; its absence
    /// proves displacement of the formerly uncommitted intent.
    pub fn publish_snapshot(
        &mut self,
        table: VoterSlotTable,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterSlotError> {
        self.publish(table, cut)
    }

    fn publish(
        &mut self,
        table: VoterSlotTable,
        cut: VoterSlotLogId,
    ) -> Result<(), VoterSlotError> {
        table.validate_successor_of(&self.table)?;
        if (cut.term == 0 && (cut.index != 0 || table.revision != 1))
            || !table_cuts_within(&table, cut)
        {
            return Err(VoterSlotError::InvalidRecord);
        }
        self.table = table;
        if self
            .intent
            .as_ref()
            .is_some_and(|intent| intent.log_id.index <= cut.index)
        {
            self.intent = None;
        }
        Ok(())
    }

    /// Restore only relevant engine fences: retired effective members plus provisional intents.
    ///
    /// Permanent inbound refusal still covers every older incarnation. Avoid
    /// materializing their unbounded historical engine IDs as live core fences.
    pub fn engine_fences(
        &self,
        effective_members: &BTreeSet<ConsensusNodeId>,
    ) -> BTreeSet<ConsensusNodeId> {
        let mut result = effective_members
            .iter()
            .copied()
            .filter(|node| self.table.is_retired(*node))
            .collect::<BTreeSet<_>>();
        if let Some(intent) = &self.intent {
            result.insert(intent.target());
        }
        result
    }

    /// Encode the canonical current Durable admission format under a fixed bound.
    pub fn encode(&self) -> Result<Vec<u8>, VoterSlotError> {
        let wire = Wire {
            table: encode_voter_slot_table(&self.table)?,
            intent: self.intent.clone(),
        };
        self.validate_intent()?;
        let encoded = crate::encode_bounded(&wire).map_err(|_| VoterSlotError::InvalidRecord)?;
        if encoded.len() + HEADER.len() > MAX_STATE_BYTES {
            return Err(VoterSlotError::TooLarge);
        }
        let mut result = HEADER.to_vec();
        result.extend(encoded);
        Ok(result)
    }

    /// Refuse unknown/old formats before interpreting any identity or gate.
    pub fn decode(bytes: &[u8]) -> Result<Self, VoterSlotError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(VoterSlotError::TooLarge);
        }
        if bytes.len() < HEADER.len() || bytes[..4] != HEADER[..4] {
            return Err(VoterSlotError::InvalidRecord);
        }
        if &bytes[..HEADER.len()] != HEADER {
            return Err(VoterSlotError::FreshInstallationRequired);
        }
        let wire: Wire = crate::decode_bounded(&bytes[HEADER.len()..])
            .map_err(|_| VoterSlotError::InvalidRecord)?;
        let result = Self {
            table: decode_voter_slot_table(&wire.table)?,
            intent: wire.intent,
        };
        result.validate_intent()?;
        Ok(result)
    }

    fn validate_intent(&self) -> Result<(), VoterSlotError> {
        if let Some(intent) = &self.intent {
            intent
                .request
                .validate()
                .map_err(|_| VoterSlotError::InvalidRecord)?;
            if intent.log_id.term == 0
                || intent.log_id.index == 0
                || intent.request.attestation.cluster_instance != self.table.cluster_instance
                || !self
                    .table
                    .slots
                    .iter()
                    .any(|slot| slot.member.identity.slot() == intent.request.attestation.slot)
            {
                return Err(VoterSlotError::InvalidRecord);
            }
            // An earlier entry may have applied since this intent was appended,
            // invalidating its CAS. That is not proof about this intent's own
            // definitive apply/truncation, so its fence must survive restart.
        }
        Ok(())
    }
}

fn table_cuts_within(table: &VoterSlotTable, cut: VoterSlotLogId) -> bool {
    let terminal = table
        .slots
        .iter()
        .filter_map(|slot| slot.last_result.as_ref().map(|result| result.terminal));
    let operation = table
        .replacement
        .as_ref()
        .into_iter()
        .flat_map(|operation| {
            let evidence = &operation.evidence;
            [
                Some(evidence.prepare),
                evidence.snapshot.as_ref().map(|snapshot| snapshot.cut),
                evidence.learner,
                evidence.caught_up,
                evidence.continuation,
                evidence.fence,
                evidence.joint,
                evidence.uniform,
            ]
            .into_iter()
            .flatten()
        });
    terminal
        .chain(operation)
        .all(|id| id.index <= cut.index && id.term <= cut.term)
}
