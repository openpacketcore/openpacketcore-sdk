use std::collections::vec_deque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::backend::{
    validate_replication_log_page_owned, ReplicationEntry, ReplicationWatchCursor,
    MAX_REPLICATION_WATCH_BACKLOG_ENTRIES, WATCH_CHANNEL_CAPACITY,
};
use crate::consumer::{
    session_consumer_change, session_consumer_change_encoded_bytes, SessionConsumerChange,
    MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES,
};
use crate::error::StoreError;

pub(crate) struct ReplicationWatcher {
    next_sequence: Option<u64>,
    sender: mpsc::Sender<Result<ReplicationEntry, StoreError>>,
}

impl ReplicationWatcher {
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Deliver exactly the next eligible live entry.
    ///
    /// Entries below the cursor can occur while a future cursor is waiting, or
    /// when an append committed before registration but its notification was
    /// waiting behind the handoff lock and is already in the captured backlog.
    /// They are ignored. A position above the expected cursor is an integrity
    /// gap and closes the watcher.
    pub(crate) fn notify(&mut self, entry: &ReplicationEntry) -> bool {
        let Some(expected) = self.next_sequence else {
            return false;
        };
        if entry.sequence < expected {
            return !self.sender.is_closed();
        }
        if entry.sequence > expected {
            let _ = self
                .sender
                .try_send(Err(StoreError::InvalidReplicationSequence));
            return false;
        }
        if self.sender.try_send(Ok(entry.clone())).is_err() {
            return false;
        }
        self.next_sequence = expected.checked_add(1);
        self.next_sequence.is_some()
    }
}

pub(crate) struct BoundedReplicationWatchStream {
    backlog: vec_deque::IntoIter<Result<ReplicationEntry, StoreError>>,
    receiver: mpsc::Receiver<Result<ReplicationEntry, StoreError>>,
}

struct QueuedConsumerWatchChange {
    change: Result<SessionConsumerChange, StoreError>,
    // The permit lives exactly as long as the entry remains in this
    // subscriber queue. It is intentionally not exposed to callers.
    _byte_permit: OwnedSemaphorePermit,
}

/// Consumer-specific watcher that receives only the already-projected change
/// envelope. Unlike [`ReplicationWatcher`], it never queues an entire replay
/// entry or its protected record/lease payload.
pub(crate) struct ConsumerReplicationWatcher {
    next_sequence: Option<u64>,
    sender: mpsc::Sender<QueuedConsumerWatchChange>,
    byte_budget: std::sync::Arc<Semaphore>,
}

impl ConsumerReplicationWatcher {
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(crate) fn notify(&mut self, change: &SessionConsumerChange, encoded_bytes: usize) -> bool {
        let Some(expected) = self.next_sequence else {
            return false;
        };
        if change.sequence() < expected {
            return !self.sender.is_closed();
        }
        if change.sequence() > expected {
            return false;
        }
        let Ok(permits) = u32::try_from(encoded_bytes.max(1)) else {
            return false;
        };
        let Ok(permit) = std::sync::Arc::clone(&self.byte_budget).try_acquire_many_owned(permits)
        else {
            return false;
        };
        if self
            .sender
            .try_send(QueuedConsumerWatchChange {
                change: Ok(change.clone()),
                _byte_permit: permit,
            })
            .is_err()
        {
            return false;
        }
        self.next_sequence = expected.checked_add(1);
        self.next_sequence.is_some()
    }
}

pub(crate) struct BoundedConsumerWatchStream {
    backlog: vec_deque::IntoIter<Result<SessionConsumerChange, StoreError>>,
    receiver: mpsc::Receiver<QueuedConsumerWatchChange>,
}

/// Return the overflow-detecting backlog query width without asking a range
/// to extend beyond the terminal sequence.
pub(crate) fn watch_backlog_query_limit(cursor: ReplicationWatchCursor) -> usize {
    let through_terminal = u64::MAX - cursor.first_sequence() + 1;
    usize::try_from(through_terminal)
        .unwrap_or(usize::MAX)
        .min(MAX_REPLICATION_WATCH_BACKLOG_ENTRIES + 1)
}

impl Stream for BoundedReplicationWatchStream {
    type Item = Result<ReplicationEntry, StoreError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(entry) = self.backlog.next() {
            return Poll::Ready(Some(entry));
        }
        self.receiver.poll_recv(cx)
    }
}

impl Stream for BoundedConsumerWatchStream {
    type Item = Result<SessionConsumerChange, StoreError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(change) = self.backlog.next() {
            return Poll::Ready(Some(change));
        }
        self.receiver
            .poll_recv(cx)
            .map(|queued| queued.map(|queued| queued.change))
    }
}

/// Build one bounded backlog and its optional live registration.
///
/// Callers install the returned watcher while still holding the same registry
/// lock that serializes append notification. The input query deliberately asks
/// for one entry beyond the limit so overflow is rejected, never truncated.
pub(crate) fn prepare_watch_registration(
    cursor: ReplicationWatchCursor,
    entries: Vec<ReplicationEntry>,
) -> Result<(BoundedReplicationWatchStream, Option<ReplicationWatcher>), StoreError> {
    let entries =
        validate_replication_log_page_owned(cursor.first_sequence(), entries.len(), entries)?;
    if entries.len() > MAX_REPLICATION_WATCH_BACKLOG_ENTRIES {
        return Err(StoreError::ReplicationWatchCatchUpRequired);
    }

    let next_sequence = entries
        .last()
        .map_or(Some(cursor.first_sequence()), |entry| {
            entry.sequence.checked_add(1)
        });
    let backlog = entries
        .into_iter()
        .map(Ok)
        .collect::<std::collections::VecDeque<_>>()
        .into_iter();
    let (sender, receiver) = mpsc::channel(WATCH_CHANNEL_CAPACITY);
    let watcher = next_sequence.map(|next_sequence| ReplicationWatcher {
        next_sequence: Some(next_sequence),
        sender,
    });
    Ok((BoundedReplicationWatchStream { backlog, receiver }, watcher))
}

/// Project one raw bounded backlog once, then register a consumer-only live
/// watcher. Every returned and queued value has a byte budget before any
/// per-consumer clone occurs.
pub(crate) fn prepare_consumer_watch_registration(
    cursor: ReplicationWatchCursor,
    entries: Vec<ReplicationEntry>,
) -> Result<
    (
        BoundedConsumerWatchStream,
        Option<ConsumerReplicationWatcher>,
    ),
    StoreError,
> {
    let entries =
        validate_replication_log_page_owned(cursor.first_sequence(), entries.len(), entries)?;
    if entries.len() > MAX_REPLICATION_WATCH_BACKLOG_ENTRIES {
        return Err(StoreError::ReplicationWatchCatchUpRequired);
    }
    let next_sequence = entries
        .last()
        .map_or(Some(cursor.first_sequence()), |entry| {
            entry.sequence.checked_add(1)
        });
    let mut retained_bytes = 0_usize;
    let mut backlog = std::collections::VecDeque::with_capacity(entries.len());
    for entry in &entries {
        let change = session_consumer_change(entry)?;
        let encoded_bytes = session_consumer_change_encoded_bytes(&change)?;
        retained_bytes = retained_bytes
            .checked_add(encoded_bytes)
            .ok_or(StoreError::ReplicationWatchCatchUpRequired)?;
        if retained_bytes > MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES {
            return Err(StoreError::ReplicationWatchCatchUpRequired);
        }
        backlog.push_back(Ok(change));
    }
    let byte_budget = std::sync::Arc::new(Semaphore::new(MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES));
    let (sender, receiver) = mpsc::channel(WATCH_CHANNEL_CAPACITY);
    let watcher = next_sequence.map(|next_sequence| ConsumerReplicationWatcher {
        next_sequence: Some(next_sequence),
        sender,
        byte_budget,
    });
    Ok((
        BoundedConsumerWatchStream {
            backlog: backlog.into_iter(),
            receiver,
        },
        watcher,
    ))
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use opc_types::Timestamp;

    use super::*;
    use crate::backend::{ReplicationOp, ReplicationTxId};

    fn entry(sequence: u64) -> ReplicationEntry {
        ReplicationEntry {
            sequence,
            tx_id: ReplicationTxId::new("watch-test").expect("transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        }
    }

    #[tokio::test]
    async fn future_and_terminal_watchers_never_emit_lower_entries() {
        let cursor = ReplicationWatchCursor::new(u64::MAX);
        let (mut stream, watcher) =
            prepare_watch_registration(cursor, Vec::new()).expect("prepare terminal watcher");
        let mut watcher = watcher.expect("live terminal watcher");
        assert!(watcher.notify(&entry(1)), "lower entry retains watcher");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stream.next())
                .await
                .is_err()
        );

        assert!(
            !watcher.notify(&entry(u64::MAX)),
            "terminal entry closes sender"
        );
        assert_eq!(
            stream
                .next()
                .await
                .expect("terminal item")
                .expect("valid terminal item")
                .sequence,
            u64::MAX
        );
        drop(watcher);
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn backlog_overflow_fails_instead_of_truncating() {
        let entries = (1..=u64::try_from(MAX_REPLICATION_WATCH_BACKLOG_ENTRIES + 1)
            .expect("bounded test width"))
            .map(entry)
            .collect();
        let error = prepare_watch_registration(ReplicationWatchCursor::new(1), entries)
            .err()
            .expect("overflow must fail");
        assert_eq!(error, StoreError::ReplicationWatchCatchUpRequired);
    }
}
