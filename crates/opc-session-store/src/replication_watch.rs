use std::collections::vec_deque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::sync::mpsc;

use crate::backend::{
    validate_replication_log_page_owned, ReplicationEntry, ReplicationWatchCursor,
    MAX_REPLICATION_WATCH_BACKLOG_ENTRIES, WATCH_CHANNEL_CAPACITY,
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
