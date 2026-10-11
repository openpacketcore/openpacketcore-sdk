use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::{Arc, Mutex};

use opc_consensus::engine::{
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
    EmptyNode, Entry, EntryPayload, LogId, LogState, RaftLogReader, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError, StoredMembership, Vote,
};

use super::ElectionConfig;

// Storage only acknowledges actual updates. Elections and quorum decisions
// remain entirely in the pinned engine; this fixture has no consensus logic.
#[derive(Clone, Default)]
pub(super) struct MemoryLog(Arc<Mutex<LogData>>);

#[derive(Default)]
struct LogData {
    entries: BTreeMap<u64, Entry<ElectionConfig>>,
    purged: Option<LogId<u64>>,
    vote: Option<Vote<u64>>,
    committed: Option<LogId<u64>>,
}

impl RaftLogReader<ElectionConfig> for MemoryLog {
    async fn try_get_log_entries<R: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: R,
    ) -> Result<Vec<Entry<ElectionConfig>>, StorageError<u64>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .entries
            .range(range)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

impl RaftLogStorage<ElectionConfig> for MemoryLog {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<ElectionConfig>, StorageError<u64>> {
        let state = self.0.lock().unwrap();
        Ok(LogState {
            last_purged_log_id: state.purged,
            last_log_id: state
                .entries
                .last_key_value()
                .map(|(_, entry)| entry.log_id)
                .or(state.purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        self.0.lock().unwrap().vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        Ok(self.0.lock().unwrap().vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<u64>>,
    ) -> Result<(), StorageError<u64>> {
        self.0.lock().unwrap().committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        Ok(self.0.lock().unwrap().committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<ElectionConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<ElectionConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut state = self.0.lock().unwrap();
        for entry in entries {
            state.entries.insert(entry.log_id.index, entry);
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.0
            .lock()
            .unwrap()
            .entries
            .retain(|index, _| *index < log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<u64>) -> Result<(), StorageError<u64>> {
        let mut state = self.0.lock().unwrap();
        state.entries.retain(|index, _| *index > log_id.index);
        state.purged = Some(log_id);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct MemoryStateMachine(Arc<Mutex<Applied>>);

#[derive(Default)]
struct Applied {
    last: Option<LogId<u64>>,
    membership: StoredMembership<u64, EmptyNode>,
    values: Vec<u64>,
}

impl MemoryStateMachine {
    pub(super) fn values(&self) -> Vec<u64> {
        self.0.lock().unwrap().values.clone()
    }
}

impl RaftStateMachine<ElectionConfig> for MemoryStateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, EmptyNode>), StorageError<u64>> {
        let state = self.0.lock().unwrap();
        Ok((state.last, state.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<u64>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<ElectionConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut state = self.0.lock().unwrap();
        let mut responses = Vec::new();
        for entry in entries {
            state.last = Some(entry.log_id);
            let response = match entry.payload {
                EntryPayload::Blank => 0,
                EntryPayload::Normal(value) => {
                    state.values.push(value);
                    value
                }
                EntryPayload::Membership(membership) => {
                    state.membership = StoredMembership::new(Some(entry.log_id), membership);
                    0
                }
            };
            responses.push(response);
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self {
        self.clone()
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ElectionConfig>>, StorageError<u64>> {
        Ok(None)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        panic!("the small election fixture must not need a snapshot")
    }

    async fn install_snapshot(
        &mut self,
        _meta: &SnapshotMeta<u64, EmptyNode>,
        _snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        panic!("the small election fixture must not need a snapshot")
    }
}

impl RaftSnapshotBuilder<ElectionConfig> for MemoryStateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<ElectionConfig>, StorageError<u64>> {
        panic!("the small election fixture must not need a snapshot")
    }
}
