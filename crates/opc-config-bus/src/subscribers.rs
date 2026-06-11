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
    DropOldest,
    DropNewest,
    DisconnectOnLag,
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

        let mut queue = self.queue.lock().expect("subscriber queue mutex poisoned");
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
        self.queue
            .lock()
            .expect("subscriber queue mutex poisoned")
            .pop_front()
    }

    pub(crate) fn len(&self) -> usize {
        self.queue
            .lock()
            .expect("subscriber queue mutex poisoned")
            .len()
    }
}

/// Receiver for config-change fanout notifications.
pub struct ConfigReceiver<C: OpcConfig> {
    pub(crate) inner: Arc<SubscriberState<C>>,
}

impl<C: OpcConfig> ConfigReceiver<C> {
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

    pub fn try_recv(&self) -> Option<ConfigEvent<C>> {
        self.inner.pop()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

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
