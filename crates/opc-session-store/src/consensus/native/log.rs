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
        Self::validate_entry_context(entry, state.identity, &state.members)
    }

    pub(super) fn validate_entry_context(
        entry: &Entry<SessionRaftTypeConfig>,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<()> {
        sql::validate_log_id(&entry.log_id)?;
        if sql::fixed_profile_entry_changes_topology(entry, members) {
            return Err(invalid("native fixed log changes topology"));
        }
        if let EntryPayload::Normal(command) = &entry.payload {
            sql::validate_command_for_log(command, identity)?;
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
                SessionMutationIntent::AdvanceLogicalTime
                    | SessionMutationIntent::MaintainFencedTransitionV2History { .. }
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
        changes::Publication::prepare(self, operation, state, frozen_applied)?.publish(self, state)
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

    pub(crate) fn validate(&self, state: &NativeState) -> io::Result<()> {
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
