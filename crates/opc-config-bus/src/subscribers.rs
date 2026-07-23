//! Bounded per-subscriber fanout queues (RFC 001 §11). Slow subscribers are
//! isolated by their configured lag policy (drop, disconnect, or forced
//! resync) so they can never block snapshot publication or other subscribers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::Notify;

use opc_config_model::OpcConfig;

use crate::types::{ConfigEvent, ConfigEventRetainedSizeError};

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
    /// current snapshot instead of replaying deltas. A byte-budgeted
    /// subscriber closes if even the replacement marker cannot fit.
    ForceResync,
}

/// Value-free reason recorded when a subscriber is disconnected by its lag
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubscriberDisconnectReason {
    /// The subscriber's configured event-count capacity was already full.
    EventCapacityExceeded,
    /// The incoming event would exceed the subscriber's retained-byte budget.
    RetainedByteBudgetExceeded,
    /// The config model did not provide the retained-size estimate required by
    /// a byte-budgeted subscriber.
    RetainedSizeUnavailable,
    /// Retained-size arithmetic overflowed while charging the incoming event.
    RetainedSizeArithmeticOverflow,
}

impl SubscriberDisconnectReason {
    /// Returns the stable, value-free diagnostic code for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventCapacityExceeded => "event-capacity-exceeded",
            Self::RetainedByteBudgetExceeded => "retained-byte-budget-exceeded",
            Self::RetainedSizeUnavailable => "retained-size-unavailable",
            Self::RetainedSizeArithmeticOverflow => "retained-size-arithmetic-overflow",
        }
    }
}

struct QueuedConfigEvent<C: OpcConfig> {
    event: ConfigEvent<C>,
    retained_bytes: usize,
}

struct SubscriberQueue<C: OpcConfig> {
    events: VecDeque<QueuedConfigEvent<C>>,
    retained_bytes: usize,
    disconnect_reason: Option<SubscriberDisconnectReason>,
}

impl<C: OpcConfig> SubscriberQueue<C> {
    fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            retained_bytes: 0,
            disconnect_reason: None,
        }
    }

    fn push(&mut self, event: ConfigEvent<C>, retained_bytes: usize) {
        self.retained_bytes = self.retained_bytes.saturating_add(retained_bytes);
        self.events.push_back(QueuedConfigEvent {
            event,
            retained_bytes,
        });
    }

    fn pop(&mut self) -> Option<ConfigEvent<C>> {
        let queued = self.events.pop_front()?;
        self.retained_bytes = self.retained_bytes.saturating_sub(queued.retained_bytes);
        Some(queued.event)
    }

    fn clear(&mut self) {
        self.events.clear();
        self.retained_bytes = 0;
    }
}

pub(crate) struct SubscriberState<C: OpcConfig> {
    pub(crate) lag_policy: SubscriberLagPolicy,
    pub(crate) capacity: usize,
    pub(crate) retained_byte_budget: Option<usize>,
    queue: Mutex<SubscriberQueue<C>>,
    pub(crate) notify: Notify,
    pub(crate) closed: AtomicBool,
}

impl<C: OpcConfig> SubscriberState<C> {
    pub(crate) fn new(
        lag_policy: SubscriberLagPolicy,
        capacity: usize,
        retained_byte_budget: Option<usize>,
    ) -> Self {
        let capacity = capacity.max(1);
        Self {
            lag_policy,
            capacity,
            retained_byte_budget,
            queue: Mutex::new(SubscriberQueue::new(capacity)),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(crate) fn enqueue(&self, event: ConfigEvent<C>) {
        let retained_size = if self.retained_byte_budget.is_some() {
            event.retained_size_bytes()
        } else {
            Ok(0)
        };
        self.enqueue_with_retained_size(event, retained_size);
    }

    pub(crate) fn enqueue_with_retained_size(
        &self,
        event: ConfigEvent<C>,
        retained_size: Result<usize, ConfigEventRetainedSizeError>,
    ) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }

        let retained_bytes = self.retained_byte_budget.map(|_| retained_size);
        let sizing_failure = retained_bytes.as_ref().and_then(|result| {
            result.as_ref().err().map(|error| match error {
                ConfigEventRetainedSizeError::SnapshotSizeUnavailable
                | ConfigEventRetainedSizeError::DeltaSizeUnavailable => {
                    SubscriberDisconnectReason::RetainedSizeUnavailable
                }
                ConfigEventRetainedSizeError::ArithmeticOverflow => {
                    SubscriberDisconnectReason::RetainedSizeArithmeticOverflow
                }
            })
        });
        let retained_bytes = match retained_bytes {
            None => 0,
            Some(Ok(retained_bytes)) => retained_bytes,
            Some(Err(_)) => 0,
        };

        let mut queue = match self.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => {
                crate::metrics::record_subscriber_notification_failure();
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner()
            }
        };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let event_capacity_exceeded = queue.events.len() >= self.capacity;
        let byte_budget_exceeded = self
            .retained_byte_budget
            .is_some_and(|budget| retained_bytes > budget.saturating_sub(queue.retained_bytes));
        let overflow_reason = sizing_failure.or_else(|| {
            byte_budget_exceeded
                .then_some(SubscriberDisconnectReason::RetainedByteBudgetExceeded)
                .or_else(|| {
                    event_capacity_exceeded
                        .then_some(SubscriberDisconnectReason::EventCapacityExceeded)
                })
        });

        if overflow_reason.is_none() {
            queue.push(event, retained_bytes);
            drop(queue);
            self.notify.notify_one();
            return;
        }

        crate::metrics::record_subscriber_notification_failure();

        match self.lag_policy {
            SubscriberLagPolicy::DropOldest => {
                let event_can_fit_byte_budget = sizing_failure.is_none()
                    && self
                        .retained_byte_budget
                        .is_none_or(|budget| retained_bytes <= budget);
                if event_can_fit_byte_budget {
                    while queue.events.len() >= self.capacity
                        || self.retained_byte_budget.is_some_and(|budget| {
                            retained_bytes > budget.saturating_sub(queue.retained_bytes)
                        })
                    {
                        if queue.pop().is_none() {
                            break;
                        }
                    }
                    let event_fits = queue.events.len() < self.capacity
                        && self.retained_byte_budget.is_none_or(|budget| {
                            retained_bytes <= budget.saturating_sub(queue.retained_bytes)
                        });
                    if event_fits {
                        queue.push(event, retained_bytes);
                        drop(queue);
                        self.notify.notify_one();
                        return;
                    }
                }
                drop(queue);
                tracing::debug!(
                    reason = overflow_reason.map(SubscriberDisconnectReason::as_str),
                    "dropping config notification that cannot fit subscriber queue"
                );
            }
            SubscriberLagPolicy::DropNewest => {
                drop(queue);
                tracing::debug!(
                    reason = overflow_reason.map(SubscriberDisconnectReason::as_str),
                    "dropping newest config notification for lagging subscriber"
                );
            }
            SubscriberLagPolicy::DisconnectOnLag => {
                queue.disconnect_reason = overflow_reason;
                self.closed.store(true, Ordering::Release);
                drop(queue);
                tracing::debug!(
                    reason = overflow_reason.map(SubscriberDisconnectReason::as_str),
                    "disconnecting lagging config subscriber"
                );
                self.notify.notify_one();
            }
            SubscriberLagPolicy::ForceResync => {
                let latest_version = event.version();
                queue.clear();
                let resync = ConfigEvent::ResyncRequired { latest_version };
                let resync_retained_bytes = if self.retained_byte_budget.is_some() {
                    std::mem::size_of::<ConfigEvent<C>>()
                } else {
                    0
                };
                if self
                    .retained_byte_budget
                    .is_none_or(|budget| resync_retained_bytes <= budget)
                {
                    queue.push(resync, resync_retained_bytes);
                } else {
                    queue.disconnect_reason =
                        Some(SubscriberDisconnectReason::RetainedByteBudgetExceeded);
                    self.closed.store(true, Ordering::Release);
                }
                drop(queue);
                self.notify.notify_one();
            }
        }
    }

    pub(crate) fn pop(&self) -> Option<ConfigEvent<C>> {
        match self.queue.lock() {
            Ok(mut queue) => queue.pop(),
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().pop()
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self.queue.lock() {
            Ok(queue) => queue.events.len(),
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().events.len()
            }
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        match self.queue.lock() {
            Ok(queue) => queue.retained_bytes,
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().retained_bytes
            }
        }
    }

    pub(crate) fn disconnect_reason(&self) -> Option<SubscriberDisconnectReason> {
        match self.queue.lock() {
            Ok(queue) => queue.disconnect_reason,
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner().disconnect_reason
            }
        }
    }

    fn close_and_discard(&self) {
        let mut queue = match self.queue.lock() {
            Ok(queue) => queue,
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber queue");
                poisoned.into_inner()
            }
        };
        queue.clear();
        self.closed.store(true, Ordering::Release);
        drop(queue);
        self.notify.notify_waiters();
    }
}

/// Receiver for config-change fanout notifications.
pub struct ConfigReceiver<C: OpcConfig> {
    pub(crate) inner: Arc<SubscriberState<C>>,
}

impl<C: OpcConfig> ConfigReceiver<C> {
    /// Awaits the next event in publication order. Returns `None` once the
    /// subscription is closed (`DisconnectOnLag` overflow, an unrepresentable
    /// `ForceResync` marker, or receiver drop) and the queue has been fully
    /// drained — events already queued by `DisconnectOnLag` are still
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
    /// `DisconnectOnLag` overflow or because a `ForceResync` marker could not
    /// fit its byte budget. No further events will be enqueued, though events
    /// retained by `DisconnectOnLag` may still be drained.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Returns the conservative retained-byte charge of queued events.
    ///
    /// This is zero for a legacy count-only subscription. For a byte-budgeted
    /// subscription it never exceeds the configured budget.
    pub fn retained_bytes(&self) -> usize {
        self.inner.retained_bytes()
    }

    /// Returns the configured conservative retained-byte budget, or `None`
    /// for a legacy count-only subscription.
    pub fn retained_byte_budget(&self) -> Option<usize> {
        self.inner.retained_byte_budget
    }

    /// Returns the value-free reason recorded when a lag policy disconnected
    /// this subscriber, if any.
    pub fn disconnect_reason(&self) -> Option<SubscriberDisconnectReason> {
        self.inner.disconnect_reason()
    }
}

impl<C: OpcConfig> Drop for ConfigReceiver<C> {
    fn drop(&mut self) {
        self.inner.close_and_discard();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConfigChange;
    use opc_config_model::{ConfigError, ValidationContext, ValidationError, YangPath};
    use opc_types::{ConfigVersion, SchemaDigest, TxId};
    use std::sync::Barrier;

    #[derive(Clone)]
    struct HeapConfig {
        payload: Vec<u64>,
    }

    #[derive(Debug)]
    struct HeapDelta {
        payload: Vec<u64>,
    }

    impl OpcConfig for HeapConfig {
        type Delta = HeapDelta;

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([1; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn subscriber_snapshot_retained_size_bytes(&self) -> Option<usize> {
            Some(
                std::mem::size_of::<Self>().saturating_add(
                    self.payload
                        .capacity()
                        .saturating_mul(std::mem::size_of::<u64>()),
                ),
            )
        }

        fn subscriber_delta_retained_size_bytes(delta: &Self::Delta) -> Option<usize> {
            Some(
                std::mem::size_of::<Self::Delta>().saturating_add(
                    delta
                        .payload
                        .capacity()
                        .saturating_mul(std::mem::size_of::<u64>()),
                ),
            )
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct UnknownSizeConfig;

    impl OpcConfig for UnknownSizeConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([2; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct OverflowSizeConfig;

    impl OpcConfig for OverflowSizeConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([3; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn subscriber_snapshot_retained_size_bytes(&self) -> Option<usize> {
            Some(usize::MAX)
        }

        fn subscriber_delta_retained_size_bytes(_delta: &Self::Delta) -> Option<usize> {
            Some(std::mem::size_of::<Self::Delta>())
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct BlockingSizeConfig {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        blocked_once: Arc<AtomicBool>,
    }

    impl OpcConfig for BlockingSizeConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([4; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn subscriber_snapshot_retained_size_bytes(&self) -> Option<usize> {
            if !self.blocked_once.swap(true, Ordering::AcqRel) {
                self.entered.wait();
                self.release.wait();
            }
            Some(std::mem::size_of::<Self>())
        }

        fn subscriber_delta_retained_size_bytes(_delta: &Self::Delta) -> Option<usize> {
            Some(std::mem::size_of::<Self::Delta>())
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    fn heap_config(capacity: usize, marker: u8) -> Arc<HeapConfig> {
        let mut payload = Vec::with_capacity(capacity);
        payload.push(u64::from(marker));
        Arc::new(HeapConfig { payload })
    }

    fn heap_event(
        previous: Arc<HeapConfig>,
        current: Arc<HeapConfig>,
        delta_capacity: usize,
        path_capacity: usize,
        version: u64,
    ) -> ConfigEvent<HeapConfig> {
        let mut delta_payload = Vec::with_capacity(delta_capacity);
        delta_payload.push(version);
        let mut path = String::with_capacity(path_capacity);
        path.push_str("/system/items/item");
        ConfigEvent::Change(ConfigChange {
            tx_id: TxId::new(),
            version: ConfigVersion::new(version),
            previous,
            current,
            deltas: Arc::from([HeapDelta {
                payload: delta_payload,
            }]),
            changed_paths: Arc::from([YangPath::new(path).expect("valid path")]),
        })
    }

    fn unknown_event() -> ConfigEvent<UnknownSizeConfig> {
        ConfigEvent::Change(ConfigChange {
            tx_id: TxId::new(),
            version: ConfigVersion::new(1),
            previous: Arc::new(UnknownSizeConfig),
            current: Arc::new(UnknownSizeConfig),
            deltas: Arc::from([]),
            changed_paths: Arc::from([]),
        })
    }

    fn overflow_event() -> ConfigEvent<OverflowSizeConfig> {
        ConfigEvent::Change(ConfigChange {
            tx_id: TxId::new(),
            version: ConfigVersion::new(1),
            previous: Arc::new(OverflowSizeConfig),
            current: Arc::new(OverflowSizeConfig),
            deltas: Arc::from([]),
            changed_paths: Arc::from([]),
        })
    }

    fn blocking_event(config: BlockingSizeConfig) -> ConfigEvent<BlockingSizeConfig> {
        ConfigEvent::Change(ConfigChange {
            tx_id: TxId::new(),
            version: ConfigVersion::new(1),
            previous: Arc::new(config.clone()),
            current: Arc::new(config),
            deltas: Arc::from([]),
            changed_paths: Arc::from([]),
        })
    }

    #[test]
    fn heap_backed_event_charge_includes_snapshots_delta_and_path_capacity() {
        let previous = heap_config(8 * 1024, 1);
        let current = heap_config(16 * 1024, 2);
        let event = heap_event(
            Arc::clone(&previous),
            Arc::clone(&current),
            4 * 1024,
            512,
            1,
        );
        let ConfigEvent::Change(change) = &event else {
            panic!("expected change event");
        };
        let heap_elements = previous
            .payload
            .capacity()
            .checked_add(current.payload.capacity())
            .and_then(|elements| elements.checked_add(change.deltas[0].payload.capacity()))
            .expect("fixture element count fits");
        let heap_bytes = heap_elements
            .checked_mul(std::mem::size_of::<u64>())
            .expect("fixture heap bytes fit");
        let expected = std::mem::size_of_val(&event)
            .checked_add(std::mem::size_of::<HeapConfig>().saturating_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HeapDelta>()))
            .and_then(|bytes| bytes.checked_add(heap_bytes))
            .and_then(|bytes| bytes.checked_add(change.changed_paths[0].retained_size_bytes()))
            .expect("fixture size fits");

        assert_eq!(event.retained_size_bytes(), Ok(expected));
        assert!(heap_bytes >= 224 * 1024);
        assert!(expected > std::mem::size_of_val(&event));
    }

    #[test]
    fn shared_snapshot_is_charged_per_event_and_released_once() {
        let first = heap_config(256, 1);
        let shared_middle = heap_config(4096, 2);
        let last = heap_config(512, 3);
        let first_event = heap_event(first, Arc::clone(&shared_middle), 128, 64, 1);
        let second_event = heap_event(Arc::clone(&shared_middle), last, 256, 64, 2);
        let first_charge = first_event.retained_size_bytes().expect("first charge");
        let second_charge = second_event.retained_size_bytes().expect("second charge");
        let budget = first_charge
            .checked_add(second_charge)
            .expect("fixture budget fits");
        let state = Arc::new(SubscriberState::new(
            SubscriberLagPolicy::DisconnectOnLag,
            4,
            Some(budget),
        ));
        let receiver = ConfigReceiver {
            inner: Arc::clone(&state),
        };

        state.enqueue(first_event);
        state.enqueue(second_event);
        assert_eq!(receiver.retained_bytes(), budget);
        assert_eq!(receiver.len(), 2);

        let _first = receiver.try_recv().expect("first event");
        assert_eq!(receiver.retained_bytes(), second_charge);
        assert_eq!(receiver.len(), 1);

        drop(receiver);
        assert_eq!(state.retained_bytes(), 0);
        assert_eq!(state.len(), 0);
        assert!(state.closed.load(Ordering::Acquire));
    }

    #[test]
    fn disconnect_rejects_single_oversized_event_before_enqueue() {
        let event = heap_event(heap_config(1024, 1), heap_config(2048, 2), 512, 64, 1);
        let charge = event.retained_size_bytes().expect("event charge");
        let state = SubscriberState::new(
            SubscriberLagPolicy::DisconnectOnLag,
            8,
            Some(charge.saturating_sub(1)),
        );

        state.enqueue(event);

        assert!(state.closed.load(Ordering::Acquire));
        assert_eq!(state.len(), 0);
        assert_eq!(state.retained_bytes(), 0);
        assert_eq!(
            state.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedByteBudgetExceeded)
        );
        assert_eq!(
            state
                .disconnect_reason()
                .map(SubscriberDisconnectReason::as_str),
            Some("retained-byte-budget-exceeded")
        );
    }

    #[tokio::test]
    async fn byte_disconnect_drains_existing_event_then_closes() {
        let first = heap_event(heap_config(64, 1), heap_config(64, 2), 64, 32, 1);
        let overflow = heap_event(heap_config(64, 3), heap_config(64, 4), 64, 32, 2);
        let first_charge = first.retained_size_bytes().expect("first charge");
        let state = Arc::new(SubscriberState::new(
            SubscriberLagPolicy::DisconnectOnLag,
            8,
            Some(first_charge),
        ));
        let receiver = ConfigReceiver {
            inner: Arc::clone(&state),
        };

        state.enqueue(first);
        state.enqueue(overflow);

        assert!(receiver.is_closed());
        assert_eq!(receiver.len(), 1);
        assert_eq!(receiver.retained_bytes(), first_charge);
        assert_eq!(
            receiver.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedByteBudgetExceeded)
        );
        assert!(matches!(
            receiver.recv().await,
            Some(ConfigEvent::Change(change)) if change.version == ConfigVersion::new(1)
        ));
        assert_eq!(receiver.retained_bytes(), 0);
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn default_unknown_size_disconnects_with_typed_reason() {
        let state = SubscriberState::new(SubscriberLagPolicy::DisconnectOnLag, 8, Some(usize::MAX));

        state.enqueue(unknown_event());

        assert!(state.closed.load(Ordering::Acquire));
        assert_eq!(state.len(), 0);
        assert_eq!(state.retained_bytes(), 0);
        assert_eq!(
            state.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedSizeUnavailable)
        );
        assert_eq!(
            state
                .disconnect_reason()
                .map(SubscriberDisconnectReason::as_str),
            Some("retained-size-unavailable")
        );
    }

    #[test]
    fn overflow_and_minimum_nonzero_budget_fail_closed() {
        let saturated =
            SubscriberState::new(SubscriberLagPolicy::DisconnectOnLag, 8, Some(usize::MAX));
        saturated.enqueue(overflow_event());
        assert!(saturated.closed.load(Ordering::Acquire));
        assert_eq!(saturated.len(), 0);
        assert_eq!(saturated.retained_bytes(), 0);
        assert_eq!(
            saturated.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedSizeArithmeticOverflow)
        );

        let minimum = SubscriberState::new(SubscriberLagPolicy::DisconnectOnLag, 8, Some(1));
        minimum.enqueue(heap_event(heap_config(1, 1), heap_config(1, 2), 1, 20, 1));
        assert!(minimum.closed.load(Ordering::Acquire));
        assert_eq!(minimum.len(), 0);
        assert_eq!(minimum.retained_bytes(), 0);
        assert_eq!(
            minimum.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedByteBudgetExceeded)
        );

        let marker_too_large = SubscriberState::new(SubscriberLagPolicy::ForceResync, 8, Some(1));
        marker_too_large.enqueue(heap_event(heap_config(1, 1), heap_config(1, 2), 1, 20, 2));
        assert!(marker_too_large.closed.load(Ordering::Acquire));
        assert_eq!(marker_too_large.len(), 0);
        assert_eq!(marker_too_large.retained_bytes(), 0);
        assert_eq!(
            marker_too_large.disconnect_reason(),
            Some(SubscriberDisconnectReason::RetainedByteBudgetExceeded)
        );
    }

    #[test]
    fn byte_pressure_preserves_each_lag_policy() {
        let small_one = heap_event(heap_config(8, 1), heap_config(8, 2), 8, 20, 1);
        let small_two = heap_event(heap_config(8, 3), heap_config(8, 4), 8, 20, 2);
        let large = heap_event(
            heap_config(8 * 1024, 5),
            heap_config(8 * 1024, 6),
            1024,
            20,
            3,
        );
        let small_charge = small_one.retained_size_bytes().expect("small charge");
        let second_small_charge = small_two.retained_size_bytes().expect("small charge");
        let large_charge = large.retained_size_bytes().expect("large charge");
        assert!(large_charge > small_charge.saturating_add(second_small_charge));

        let drop_oldest =
            SubscriberState::new(SubscriberLagPolicy::DropOldest, 8, Some(large_charge));
        drop_oldest.enqueue(small_one);
        drop_oldest.enqueue(small_two);
        assert_eq!(
            drop_oldest.retained_bytes(),
            small_charge.saturating_add(second_small_charge)
        );
        drop_oldest.enqueue(large);
        assert_eq!(drop_oldest.len(), 1);
        assert_eq!(drop_oldest.retained_bytes(), large_charge);
        assert!(matches!(
            drop_oldest.pop(),
            Some(ConfigEvent::Change(change)) if change.version == ConfigVersion::new(3)
        ));
        assert_eq!(drop_oldest.retained_bytes(), 0);

        let keep = heap_event(heap_config(8, 1), heap_config(8, 2), 8, 20, 4);
        let reject = heap_event(heap_config(8, 3), heap_config(8, 4), 8, 20, 5);
        let keep_charge = keep.retained_size_bytes().expect("keep charge");
        let drop_newest =
            SubscriberState::new(SubscriberLagPolicy::DropNewest, 8, Some(keep_charge));
        drop_newest.enqueue(keep);
        drop_newest.enqueue(reject);
        assert_eq!(drop_newest.len(), 1);
        assert_eq!(drop_newest.retained_bytes(), keep_charge);
        assert!(matches!(
            drop_newest.pop(),
            Some(ConfigEvent::Change(change)) if change.version == ConfigVersion::new(4)
        ));

        let first = heap_event(heap_config(8, 1), heap_config(8, 2), 8, 20, 6);
        let overflow = heap_event(heap_config(8, 3), heap_config(8, 4), 8, 20, 7);
        let first_charge = first.retained_size_bytes().expect("first charge");
        let force_resync =
            SubscriberState::new(SubscriberLagPolicy::ForceResync, 8, Some(first_charge));
        force_resync.enqueue(first);
        force_resync.enqueue(overflow);
        assert_eq!(force_resync.len(), 1);
        assert_eq!(
            force_resync.retained_bytes(),
            std::mem::size_of::<ConfigEvent<HeapConfig>>()
        );
        assert!(matches!(
            force_resync.pop(),
            Some(ConfigEvent::ResyncRequired { latest_version })
                if latest_version == ConfigVersion::new(7)
        ));
        assert_eq!(force_resync.retained_bytes(), 0);
    }

    #[test]
    fn receiver_drop_wins_enqueue_between_closed_checks() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let event = blocking_event(BlockingSizeConfig {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            blocked_once: Arc::new(AtomicBool::new(false)),
        });
        let state = Arc::new(SubscriberState::new(
            SubscriberLagPolicy::DisconnectOnLag,
            2,
            Some(usize::MAX),
        ));
        let receiver = ConfigReceiver {
            inner: Arc::clone(&state),
        };

        let enqueue_state = Arc::clone(&state);
        let enqueue = std::thread::spawn(move || enqueue_state.enqueue(event));
        entered.wait();
        drop(receiver);
        release.wait();
        enqueue.join().expect("enqueue thread");

        assert!(state.closed.load(Ordering::Acquire));
        assert_eq!(state.len(), 0);
        assert_eq!(state.retained_bytes(), 0);
    }
}
