//! Ordered, exact encoded Raft log state. This is an admission view, never a
//! business read authority. Only the WAL owner's separately published durable
//! committed watermark authorizes application.

use imbl::OrdMap;

use bytes::Bytes;
use opc_consensus::engine::Vote;

use super::*;
use crate::sqlite::consensus::{self as sql, wal::Operation};

mod changes;
mod read;
mod resident;
pub(super) use changes::CapturedLog;
pub(super) use changes::GenerationLogVersion;
pub(super) use changes::{validate_context_metadata, LogFrontiers};
pub(crate) use resident::NativeLogEntry;

pub(super) fn fingerprint(index: u64, encoded: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut content = Sha256::new();
    content.update(b"OPC-native-log-row-v1\0");
    content.update(index.to_le_bytes());
    content.update((encoded.len() as u64).to_le_bytes());
    content.update(encoded);
    content.finalize().into()
}

pub(crate) const MAX_RETAINED_LOG_ENTRIES: usize = 1_048_576;

/// A logical purge may advance while its physical rows remain necessary for
/// replay from the installed origin. Only that authenticated full LogId or
/// the exact purge boundary can witness a non-genesis physical prefix.
pub(super) fn validate_retained_prefix(
    first: LogId<SessionConsensusNodeId>,
    purged: Option<LogId<SessionConsensusNodeId>>,
    origin: Option<&NativeSnapshotAuthority>,
) -> io::Result<()> {
    if first.index == 0 {
        return Ok(());
    }
    let adjacent =
        |cut: &LogId<SessionConsensusNodeId>| cut.index.checked_add(1) == Some(first.index);
    let predecessor = purged
        .filter(adjacent)
        .or_else(|| origin.and_then(|origin| origin.candidate().0.last_log_id.filter(adjacent)))
        .ok_or_else(|| invalid("native retained log lacks its prefix"))?;
    sql::ensure_log_id_not_after(
        &predecessor,
        &first,
        "native retained log prefix lineage differs",
    )
}

#[derive(Default)]
pub(crate) struct NativeLog {
    pub(crate) entries: OrdMap<u64, SharedRow<NativeLogEntry>>,
    pub(crate) vote: Option<Vote<SessionConsensusNodeId>>,
    pub(crate) committed: Option<LogId<SessionConsensusNodeId>>,
    pub(crate) purged: Option<LogId<SessionConsensusNodeId>>,
    pub(crate) slot_intent: Option<LogId<SessionConsensusNodeId>>,
    // Only selected rows with decoded unapplied slot facts. A checkpoint
    // captures this persistent root without traversing historical log rows.
    pub(super) slot_projections: OrdMap<u64, SharedRow<NativeLogEntry>>,
    // Process-local admission proofs never authorize business application or
    // survive decoding. A clone shares immutable rows but starts no journal.
    proof: Option<std::sync::Arc<changes::LogProof>>,
    changes: Option<changes::LogChanges>,
}

impl Clone for NativeLog {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            vote: self.vote,
            committed: self.committed,
            purged: self.purged,
            slot_intent: self.slot_intent,
            slot_projections: self.slot_projections.clone(),
            proof: self.proof.clone(),
            changes: None,
        }
    }
}

impl NativeLog {
    pub(crate) fn last(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.entries
            .get_max()
            .map(|(_, entry)| entry.id())
            .or(self.purged)
    }

    #[cfg(test)]
    pub(crate) fn read(
        &self,
        start: u64,
        end: Option<u64>,
        limit: Option<usize>,
    ) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
        let start = self
            .purged
            .map_or(start, |floor| start.max(floor.index + 1));
        let end = end.unwrap_or(COUNTER_MAX + 1);
        if start >= end {
            return Ok(Vec::new());
        }
        self.entries
            .range(start..end)
            .take(limit.unwrap_or(MAX_RETAINED_LOG_ENTRIES))
            .map(|(_, entry)| entry.resident().map(|row| row.entry.clone()))
            .collect()
    }

    fn exact(&self, id: LogId<SessionConsensusNodeId>) -> io::Result<()> {
        sql::validate_log_id(&id)?;
        match self.entries.get(&id.index) {
            Some(entry) if entry.id() == id => Ok(()),
            None if self.purged == Some(id) => Ok(()),
            _ => Err(invalid("native log pointer lacks exact retained lineage")),
        }
    }

    pub(crate) fn validate_entry(
        entry: &Entry<SessionRaftTypeConfig>,
        state: &NativeState,
    ) -> io::Result<()> {
        if matches!(&entry.payload, EntryPayload::Normal(command)
            if command.intent.contains_fenced_transition_v2_void())
            && state.frontiers.fenced_transition_profile != FencedTransitionV2Profile::V2WithVoid
        {
            return Err(invalid("native store profile does not permit void"));
        }
        Self::validate_entry_profile(
            entry,
            state.identity,
            &state.members,
            state.frontiers.voter_slots.is_some(),
        )
    }

    #[cfg(test)]
    pub(super) fn validate_entry_context(
        entry: &Entry<SessionRaftTypeConfig>,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<()> {
        Self::validate_entry_profile(entry, identity, members, false)
    }

    pub(super) fn validate_entry_profile(
        entry: &Entry<SessionRaftTypeConfig>,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        slots: bool,
    ) -> io::Result<()> {
        sql::validate_log_id(&entry.log_id)?;
        if slots {
            if let EntryPayload::Membership(membership) = &entry.payload {
                let expected = members
                    .iter()
                    .map(|node| {
                        opc_consensus::voter_slots::VoterSlotIdentity::from_node_id(*node)
                            .map(|id| id.slot())
                    })
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|_| invalid("native slot genesis invalid"))?;
                let configs = membership.get_joint_config();
                if !(1..=2).contains(&configs.len())
                    || membership.nodes().count() > members.len() + 1
                    || configs.iter().any(|config| config.len() != members.len())
                    || membership.nodes().any(|(node, _)| {
                        opc_consensus::voter_slots::VoterSlotIdentity::from_node_id(*node)
                            .map_or(true, |id| !expected.contains(&id.slot()))
                    })
                {
                    return Err(invalid("native slot membership shape invalid"));
                }
                return Ok(());
            }
            if let EntryPayload::Normal(command) = &entry.payload {
                if voter_slots::control(command, identity)?.is_some() {
                    return Ok(());
                }
            }
        }
        if sql::fixed_profile_entry_changes_topology(entry, members) {
            return Err(invalid("native fixed log changes topology"));
        }
        if let EntryPayload::Normal(command) = &entry.payload {
            sql::validate_command_for_log(command, identity)?;
            if let SessionMutationIntent::AsyncRecoveryBoundary {
                era,
                plan,
                protected,
            } = &command.intent
            {
                let mut boundary =
                    super::async_recovery::Boundary::from_entry(*era, *plan, entry.log_id);
                boundary.protected = protected.clone();
                return boundary.validate();
            }
            if sql::contains_protected_roster_command(&command.intent) {
                sql::protected_roster_command_for_scope(
                    &command.intent,
                    &super::roster::fixed_scope(identity, members),
                    identity,
                    entry.log_id.index,
                    sql::ProtectedRosterCommandAuthorityValidation::CurrentOnly,
                )?
                .ok_or_else(|| invalid("native roster log command is missing"))?;
                return Ok(());
            }
            if matches!(&command.intent,SessionMutationIntent::Authorized { mutation,.. }
                if matches!(mutation.as_ref(),SessionMutationIntent::MaintainFencedTransitionV2History { .. }))
            {
                return Err(invalid(
                    "native history maintenance must be a raw internal command",
                ));
            }
            let intent = match &command.intent {
                SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
                intent => intent,
            };
            if !matches!(
                intent,
                SessionMutationIntent::ScopeBatch(_)
                    | SessionMutationIntent::ScopeBatchCancel(_)
                    | SessionMutationIntent::ActivateScopeProfile(_)
                    | SessionMutationIntent::ScopeAuthority(_)
                    | SessionMutationIntent::AdvanceLogicalTime
                    | SessionMutationIntent::MaintainFencedTransitionV2History { .. }
                    | SessionMutationIntent::VoidFencedTransitionV2(_)
                    | SessionMutationIntent::ActivateVoidFencedTransitionV2 { .. }
                    | SessionMutationIntent::FencedTransitionV2(_)
                    | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
                    | SessionMutationIntent::FencedTransitionV2Batch(_)
                    | SessionMutationIntent::FencedTransition(_)
                    | SessionMutationIntent::ActivateFencedTransition { .. }
                    | SessionMutationIntent::ActivateFencedTransitionCapability { .. }
                    | SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. }
                    | SessionMutationIntent::BindConsumerRequest { .. }
                    | SessionMutationIntent::ReadConsumerRecord { .. }
                    | SessionMutationIntent::CompareAndSet(_)
                    | SessionMutationIntent::DeleteFenced(_)
                    | SessionMutationIntent::RefreshTtl { .. }
                    | SessionMutationIntent::AcquireLease { .. }
                    | SessionMutationIntent::RenewLease { .. }
                    | SessionMutationIntent::ReleaseLease(_)
            ) {
                return Err(invalid("native private log command is not implemented"));
            }
        }
        Ok(())
    }

    /// Validate and stage the whole admission operation before publishing its
    /// rows, frontiers and the same immutable objects to change capture.
    pub(crate) fn project(
        &mut self,
        operation: &Operation,
        state: &NativeState,
        frozen_applied: Option<LogId<SessionConsensusNodeId>>,
    ) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        self.project_reserved(operation, state, frozen_applied, None)
    }

    pub(crate) fn project_reserved(
        &mut self,
        operation: &Operation,
        state: &NativeState,
        frozen_applied: Option<LogId<SessionConsensusNodeId>>,
        reservation: Option<crate::sqlite::consensus::wal::async_authority::Reservation>,
    ) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        self.project_guarded(operation, state, frozen_applied, reservation, None)
    }

    pub(crate) fn project_guarded(
        &mut self,
        operation: &Operation,
        state: &NativeState,
        frozen_applied: Option<LogId<SessionConsensusNodeId>>,
        reservation: Option<crate::sqlite::consensus::wal::async_authority::Reservation>,
        fence: Option<&dyn Fn(&opc_consensus::voter_slots::VoterReplacementRequest) -> bool>,
    ) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        let publication = changes::Publication::prepare(self, operation, state, frozen_applied)?;
        if let Some(check) = fence {
            publication.check_voter_fence(check, state.identity)?;
        }
        if let Some(reservation) = reservation {
            publication.check_async_reservation(reservation)?;
        }
        publication.publish(self, state)
    }

    pub(crate) fn require_committed_entries(
        &self,
        state: &NativeState,
        durable: Option<LogId<SessionConsensusNodeId>>,
        entries: &[Entry<SessionRaftTypeConfig>],
    ) -> io::Result<()> {
        self.require_proof(state)?;
        let Some(last) = entries.last() else {
            return Ok(());
        };
        let durable =
            durable.ok_or_else(|| invalid("native application lacks durable committed cut"))?;
        sql::ensure_log_id_not_after(
            &last.log_id,
            &durable,
            "native application exceeds durable committed cut",
        )?;
        self.exact(durable)?;
        let first = state.applied().map_or(0, |applied| applied.index + 1);
        for (next, entry) in (first..).zip(entries) {
            if entry.log_id.index != next {
                return Err(invalid("native application is not contiguous"));
            }
            let persisted = self
                .entries
                .get(&next)
                .ok_or_else(|| invalid("native committed entry missing"))?;
            let encoded = serde_json::to_vec(entry)
                .map_err(|_| invalid("native committed input cannot encode"))?;
            if !persisted.matches_bytes(next, &encoded)? {
                return Err(invalid("native application bytes differ from durable log"));
            }
        }
        Ok(())
    }

    /// Admit one coherent read cut using the fixed frontier witnesses. The
    /// separate proofs certify their own roots; these equations also bind the
    /// applied business position and membership to this exact committed log.
    /// Cold membership witnesses carry admitted metadata, so no historical
    /// payload is read or retained here.
    pub(super) fn require_coherent_business<'a>(
        &self,
        state: &'a NativeState,
    ) -> io::Result<&'a Arc<super::changes::BusinessProof>> {
        let (business, _) = self.require_proofs(state)?;
        changes::validate_context(
            &changes::LogFrontiers::of(self),
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            |index| self.entries.get(&index),
        )?;
        Ok(business)
    }

    pub(crate) fn validate(&self, state: &NativeState) -> io::Result<()> {
        self.validate_slot_intent(state)?;
        let mut previous: Option<LogId<SessionConsensusNodeId>> = None;
        for (index, row) in &self.entries {
            Self::validate_row(*index, row, state)?;
            if let Some(prior) = previous {
                if *index != prior.index + 1 {
                    return Err(invalid("native retained log contains a hole"));
                }
                sql::ensure_log_id_not_after(
                    &prior,
                    &row.id(),
                    "native retained log term regressed",
                )?;
            } else {
                validate_retained_prefix(row.id(), self.purged, state.snapshot_origin.as_deref())?;
            }
            previous = Some(row.id());
        }
        changes::validate_context(
            &changes::LogFrontiers::of(self),
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            |index| self.entries.get(&index),
        )?;
        Ok(())
    }
}
