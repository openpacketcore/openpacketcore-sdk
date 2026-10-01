//! Preserve a completed native JSON size check with its immutable owned input.

use super::{committed_apply_batch_end, io, ConfigRaftTypeConfig, Entry, SqliteWorkCancellation};

/// Private apply input. Only `select` can produce the checked state; converting
/// a raw entry vector always requires full sizing at the apply boundary.
pub(crate) struct ApplyBatch {
    entries: BatchEntries,
}

enum BatchEntries {
    Unchecked(Vec<Entry<ConfigRaftTypeConfig>>),
    Checked(Vec<Entry<ConfigRaftTypeConfig>>),
}

impl From<Vec<Entry<ConfigRaftTypeConfig>>> for ApplyBatch {
    fn from(entries: Vec<Entry<ConfigRaftTypeConfig>>) -> Self {
        Self {
            entries: BatchEntries::Unchecked(entries),
        }
    }
}

impl ApplyBatch {
    /// Select one bounded whole-entry prefix and move its remainder unchanged.
    /// The proof covers sizes only: apply must still validate authority,
    /// commands, membership and the current cancellation state.
    pub(crate) fn select(
        mut entries: Vec<Entry<ConfigRaftTypeConfig>>,
        cancellation: &SqliteWorkCancellation,
    ) -> io::Result<(Self, Vec<Entry<ConfigRaftTypeConfig>>)> {
        let end = committed_apply_batch_end(&entries, cancellation)?;
        cancellation.check_io()?;
        let mut remainder = Vec::new();
        remainder
            .try_reserve_exact(entries.len() - end)
            .map_err(|_| io::Error::other("config consensus apply remainder allocation failed"))?;
        remainder.extend(entries.drain(end..));
        cancellation.check_io()?;
        Ok((
            Self {
                entries: BatchEntries::Checked(entries),
            },
            remainder,
        ))
    }

    pub(crate) fn last_log_index(&self) -> Option<u64> {
        self.entries().last().map(|entry| entry.log_id.index)
    }

    pub(super) fn needs_sizing(&self) -> bool {
        matches!(&self.entries, BatchEntries::Unchecked(_))
    }

    pub(super) fn entries(&self) -> &Vec<Entry<ConfigRaftTypeConfig>> {
        match &self.entries {
            BatchEntries::Unchecked(entries) | BatchEntries::Checked(entries) => entries,
        }
    }

    pub(super) fn into_entries(self) -> Vec<Entry<ConfigRaftTypeConfig>> {
        match self.entries {
            BatchEntries::Unchecked(entries) | BatchEntries::Checked(entries) => entries,
        }
    }
}
