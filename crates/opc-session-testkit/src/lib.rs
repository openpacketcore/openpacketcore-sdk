//! Chaos and failure testing testkit for OpenPacketCore session replication (RFC 004).
//!
//! Provides clock skew, network partition, and fault injection fixtures.
//! This is an internal testkit crate and is not published.

use std::sync::Arc;
use std::time::Duration;

use opc_session_store::{
    Clock, FakeSessionBackend, FencedSessionReplica, QuorumSessionStore, TokioVirtualClock,
};
use opc_types::Timestamp;

/// A SkewableClock wraps a virtual clock and allows injecting positive or negative clock skew.
#[derive(Debug, Clone)]
pub struct SkewableClock {
    base: Arc<TokioVirtualClock>,
    skew: Arc<std::sync::Mutex<Duration>>,
    negative: Arc<std::sync::Mutex<bool>>,
}

impl SkewableClock {
    pub fn new() -> Self {
        Self {
            base: Arc::new(TokioVirtualClock::new()),
            skew: Arc::new(std::sync::Mutex::new(Duration::from_secs(0))),
            negative: Arc::new(std::sync::Mutex::new(false)),
        }
    }

    pub fn with_base(base: Arc<TokioVirtualClock>) -> Self {
        Self {
            base,
            skew: Arc::new(std::sync::Mutex::new(Duration::from_secs(0))),
            negative: Arc::new(std::sync::Mutex::new(false)),
        }
    }

    /// Set positive or negative clock skew on this clock.
    pub fn set_skew(&self, skew: Duration, negative: bool) {
        *self.skew.lock().unwrap() = skew;
        *self.negative.lock().unwrap() = negative;
    }
}

impl Default for SkewableClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SkewableClock {
    fn now_utc(&self) -> Timestamp {
        let base_ts = self.base.now_utc();
        let skew = *self.skew.lock().unwrap();
        let neg = *self.negative.lock().unwrap();

        let odt = *base_ts.as_offset_datetime();
        let time_skew = time::Duration::seconds_f64(skew.as_secs_f64());
        let skewed = if neg {
            odt - time_skew
        } else {
            odt + time_skew
        };
        // Truncate nanoseconds to 0 to align times across replicas during concurrent operations
        let truncated = time::OffsetDateTime::from_unix_timestamp(skewed.unix_timestamp()).unwrap();
        Timestamp::from(truncated)
    }
}

/// Testkit for HA and chaos testing of the Session Store.
pub struct ChaosTestkit {
    pub replicas: Vec<FencedSessionReplica>,
    pub clocks: Vec<SkewableClock>,
}

impl ChaosTestkit {
    /// Create a new testkit with a cluster of `num_replicas` fake backends.
    pub fn new(num_replicas: usize) -> Self {
        let base_clock = Arc::new(TokioVirtualClock::new());
        let mut replicas = Vec::with_capacity(num_replicas);
        let mut clocks = Vec::with_capacity(num_replicas);

        for i in 0..num_replicas {
            let clock = SkewableClock::with_base(base_clock.clone());
            clocks.push(clock.clone());

            let raw_backend = FakeSessionBackend::new().with_clock(Arc::new(clock));
            replicas.push(FencedSessionReplica::new(i, Arc::new(raw_backend)));
        }

        Self { replicas, clocks }
    }

    /// Build a QuorumSessionStore coordinator client.
    /// You can specify which replica IDs this client is capable of reaching. Replicas not in
    /// `reached_replica_ids` will be marked offline from this client's point of view.
    pub fn build_coordinator(&self, reached_replica_ids: &[usize]) -> QuorumSessionStore {
        let mut view_replicas = Vec::new();
        for replica in &self.replicas {
            let mut wrapped_replica = replica.clone();
            let reached = reached_replica_ids.contains(&replica.id);
            wrapped_replica.client_online = Arc::new(tokio::sync::Mutex::new(reached));
            view_replicas.push(wrapped_replica);
        }
        QuorumSessionStore::new(view_replicas)
    }

    /// Set replication lag (delayed responses) on a specific replica.
    pub async fn set_lag(&self, replica_id: usize, lag: Option<Duration>) {
        if let Some(r) = self
            .replicas
            .iter()
            .find(|replica| replica.id == replica_id)
        {
            r.set_lag(lag).await;
        }
    }

    /// Set whether a replica is online or offline.
    pub async fn set_online(&self, replica_id: usize, online: bool) {
        if let Some(r) = self
            .replicas
            .iter()
            .find(|replica| replica.id == replica_id)
        {
            r.set_node_online(online).await;
        }
    }

    /// Adjust the clock skew on a specific replica.
    pub fn set_clock_skew(&self, replica_id: usize, skew: Duration, negative: bool) {
        if replica_id < self.clocks.len() {
            self.clocks[replica_id].set_skew(skew, negative);
        }
    }
}
