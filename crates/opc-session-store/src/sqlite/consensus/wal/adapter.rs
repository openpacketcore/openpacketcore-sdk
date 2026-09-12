//! Private adapter implementing the pinned Openraft storage-v2 contract.
//!
//! The writer owns each actual `LogFlushed` callback from admission through
//! its durable cut or terminal failure. No relay task or blocking-pool job
//! owns a callback. Awaited metadata uses a cancellation-safe oneshot whose
//! sender stays with the same ordered writer. Production construction remains
//! gated on state-machine, snapshot and migration integration.

use std::io;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use opc_consensus::engine::storage::{LogFlushed, RaftLogStorage};
use opc_consensus::engine::{
    Entry, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader, StorageError, Vote,
};
use opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES;

use super::{encode_json, ensure_readable, invalid_data, lock_state, Operation, Wal, MAX_ENTRIES};
use crate::sqlite::consensus::{self, SessionConsensusNodeId, SessionRaftTypeConfig};

#[derive(Clone)]
pub(crate) struct WalLogStore {
    wal: Arc<Wal>,
}

impl WalLogStore {
    pub(crate) fn new(wal: Arc<Wal>) -> Self {
        Self { wal }
    }

    fn with_read<T>(
        &self,
        read: impl FnOnce(&rusqlite::Connection) -> io::Result<T>,
    ) -> io::Result<T> {
        let state = lock_state(&self.wal.shared)?;
        ensure_readable(&state)?;
        state
            .authority
            .validate(&state.conn, self.wal.binding.identity)?;
        read(&state.conn)
    }

    async fn persist(&self, operation: Operation) -> io::Result<()> {
        self.wal
            .submit_adapter_async(operation)?
            .wait()
            .await
            .map(|_| ())
    }
}

fn error(
    subject: ErrorSubject<SessionConsensusNodeId>,
    verb: ErrorVerb,
    error: io::Error,
) -> StorageError<SessionConsensusNodeId> {
    StorageError::from_io_error(subject, verb, error)
}

fn half_open(range: &impl RangeBounds<u64>) -> io::Result<(u64, Option<u64>)> {
    let next = |value: &u64| {
        value
            .checked_add(1)
            .ok_or_else(|| invalid_data("session consensus log range overflow"))
    };
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => next(value)?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => Some(next(value)?),
        Bound::Excluded(value) => Some(*value),
        Bound::Unbounded => None,
    };
    Ok((start, end))
}

impl RaftLogReader<SessionRaftTypeConfig> for WalLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let (start, end) =
            half_open(&range).map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause))?;
        if self.wal.is_native() {
            return self
                .wal
                .native_log_read(start, end, None)
                .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause));
        }
        self.with_read(|conn| {
            if end.is_some_and(|end| start >= end) {
                return Ok(Vec::new());
            }
            consensus::read_log_range_sync(conn, self.wal.binding.identity, start, end, None)
        })
        .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause))
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        if self.wal.is_native() {
            let result = self
                .wal
                .native_log_read(start, Some(end), Some(DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES))
                .and_then(|entries| {
                    if start < end && entries.is_empty() {
                        Err(invalid_data(
                            "native limited nonempty log range returned no entry",
                        ))
                    } else {
                        Ok(entries)
                    }
                });
            return result.map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause));
        }
        self.with_read(|conn| {
            if start >= end {
                return Ok(Vec::new());
            }
            let entries = consensus::read_limited_log_range_sync(
                conn,
                self.wal.binding.identity,
                start,
                end,
                DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
            )?;
            if entries.is_empty() {
                return Err(invalid_data(
                    "session consensus limited nonempty log range returned no entry",
                ));
            }
            Ok(entries)
        })
        .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause))
    }
}

impl RaftLogStorage<SessionRaftTypeConfig> for WalLogStore {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<LogState<SessionRaftTypeConfig>, StorageError<SessionConsensusNodeId>> {
        if self.wal.is_native() {
            return self
                .wal
                .native_log_state()
                .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause));
        }
        self.with_read(|conn| {
            Ok(LogState {
                last_purged_log_id: consensus::read_purged_sync(conn, self.wal.binding.identity)?,
                last_log_id: consensus::last_log_sync(conn, self.wal.binding.identity)?,
            })
        })
        .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause))
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        self.persist(Operation::Vote(*vote))
            .await
            .map_err(|cause| error(ErrorSubject::Vote, ErrorVerb::Write, cause))
    }

    async fn read_vote(
        &mut self,
    ) -> Result<Option<Vote<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        self.wal
            .vote()
            .map_err(|cause| error(ErrorSubject::Vote, ErrorVerb::Read, cause))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<SessionConsensusNodeId>>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        self.persist(Operation::Committed(committed))
            .await
            .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Write, cause))
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        self.wal
            .committed()
            .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Read, cause))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<SessionRaftTypeConfig>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        // Bound iterator consumption before retaining all caller-owned rows.
        let result = (|| {
            let mut encoded = Vec::new();
            for entry in entries {
                if encoded.len() >= MAX_ENTRIES {
                    return Err(invalid_data("private WAL append count exceeds limit"));
                }
                let entry = encode_json(&entry)?;
                if entry.is_empty() || entry.len() > super::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES {
                    return Err(invalid_data("private WAL entry size exceeds limit"));
                }
                encoded.push(entry.into());
            }
            Ok(if encoded.is_empty() {
                Operation::Barrier
            } else {
                Operation::Append(encoded)
            })
        })();
        let operation = match result {
            Ok(operation) => operation,
            Err(cause) => {
                callback
                    .log_io_completed(Err(io::Error::other("session consensus log append failed")));
                return Err(error(ErrorSubject::Logs, ErrorVerb::Write, cause));
            }
        };
        // Returning establishes pending read visibility. Success completion
        // remains exclusively owned by the file writer's published cut.
        self.wal
            .append_callback(operation, callback)
            .map_err(|cause| error(ErrorSubject::Logs, ErrorVerb::Write, cause))
    }

    async fn truncate(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        self.persist(Operation::Truncate(log_id))
            .await
            .map_err(|cause| error(ErrorSubject::Log(log_id), ErrorVerb::Delete, cause))
    }

    async fn purge(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        // The private frozen basis admits only already-applied coverage. The
        // production adapter must also keep its apply wait and sidecar fence.
        self.persist(Operation::Purge(log_id))
            .await
            .map_err(|cause| error(ErrorSubject::Log(log_id), ErrorVerb::Delete, cause))
    }
}
