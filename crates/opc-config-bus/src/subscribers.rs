//! Bounded per-subscriber fanout queues (RFC 001 §11). Slow subscribers are
//! isolated by their configured lag policy (drop, disconnect, or forced
//! resync) so they can never block snapshot publication or other subscribers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::Notify;

use opc_config_model::OpcConfig;

use crate::types::ConfigEvent;

/// Policy applied when a subscriber's bounded queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberLagPolicy {
    /// Evict the oldest queued event to make room for the new one. The
    /// subscriber always sees the most recent changes but silently loses the
    /// oldest unprocessed deltas, so it must tolerate gaps.
    DropOldest,
    /// Discard the incoming event and keep the backlog. Preserves the oldest
    /// unprocessed deltas but the subscriber misses the newest commits until
    /// it drains and compares versions against the snapshot.
    DropNewest,
    /// Mark the subscriber closed on the first overflow: `recv` drains the
    /// already-queued events and then returns `None`. For consumers that
    /// prefer an explicit reconnect over silently missing changes.
    DisconnectOnLag,
    /// Clear the entire backlog and replace it with a single
    /// `ResyncRequired` event, forcing the subscriber to reload from the
    /// current snapshot instead of replaying deltas.
    ForceResync,
}

pub(crate) struct SubscriberState<C: OpcConfig> {
    pub(crate) lag_policy: SubscriberLagPolicy,
    pub(crate) capacity: usize,
    pub(crate) queue: Mutex<VecDeque<ConfigEvent<C>>>,
    pub(crate) notify: Notify,
    pub(crate) closed: AtomicBool,
}

impl<C: OpcConfig> SubscriberState<C> {
    pub(crate) fn new(lag_policy: SubscriberLagPolicy, capacity: usize) -> Self {
        Self {
            lag_policy,
            capacity,
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn enqueue(&self, event: ConfigEvent<C>) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let mut queue = match self.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => {
                crate::metrics::record_subscriber_notification_failure();
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner()
            }
        };
        if queue.len() < self.capacity {
            queue.push_back(event);
            drop(queue);
            self.notify.notify_one();
            return;
        }

        crate::metrics::record_subscriber_notification_failure();

        match self.lag_policy {
            SubscriberLagPolicy::DropOldest => {
                queue.pop_front();
                queue.push_back(event);
                drop(queue);
                self.notify.notify_one();
            }
            SubscriberLagPolicy::DropNewest => {
                let latest_version = event.version();
                drop(queue);
                tracing::debug!(
                    latest_version = %latest_version,
                    "dropping newest config notification for lagging subscriber"
                );
            }
            SubscriberLagPolicy::DisconnectOnLag => {
                self.closed.store(true, Ordering::Release);
                drop(queue);
                self.notify.notify_one();
            }
            SubscriberLagPolicy::ForceResync => {
                let latest_version = event.version();
                queue.clear();
                queue.push_back(ConfigEvent::ResyncRequired { latest_version });
                drop(queue);
                self.notify.notify_one();
            }
        }
    }

    pub(crate) fn pop(&self) -> Option<ConfigEvent<C>> {
        match self.queue.lock() {
            Ok(mut queue) => queue.pop_front(),
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().pop_front()
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self.queue.lock() {
            Ok(queue) => queue.len(),
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().len()
            }
        }
    }
}

/// Receiver for config-change fanout notifications.
pub struct ConfigReceiver<C: OpcConfig> {
    pub(crate) inner: Arc<SubscriberState<C>>,
}

impl<C: OpcConfig> ConfigReceiver<C> {
    /// Awaits the next event in publication order. Returns `None` once the
    /// subscription is closed (`DisconnectOnLag` overflow or receiver drop)
    /// and the queue has been fully drained — already-queued events are still
    /// delivered before the `None`.
    pub async fn recv(&self) -> Option<ConfigEvent<C>> {
        loop {
            let notified = self.inner.notify.notified();

            if let Some(event) = self.inner.pop() {
                return Some(event);
            }

            if self.inner.closed.load(Ordering::Acquire) {
                return None;
            }

            notified.await;
        }
    }

    /// Pops the next queued event without waiting; `None` means the queue is
    /// currently empty, not that the subscription is closed — check
    /// `is_closed` to distinguish the two.
    pub fn try_recv(&self) -> Option<ConfigEvent<C>> {
        self.inner.pop()
    }

    /// Returns the number of undelivered events; the queue is bounded by the
    /// capacity passed to `subscribe`, and reaching it triggers this
    /// subscriber's lag policy on the next publication.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` when no events are queued; with a fallible subscriber
    /// this is the precondition for trusting that its applied version matches
    /// the bus version.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` once the subscription has been severed by a
    /// `DisconnectOnLag` overflow; no further events will be enqueued, though
    /// earlier ones may still be drained.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }
}

impl<C: OpcConfig> Drop for ConfigReceiver<C> {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }
}
