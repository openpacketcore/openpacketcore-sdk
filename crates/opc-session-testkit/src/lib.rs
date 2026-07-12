//! Chaos and failure testing testkit for OpenPacketCore session replication (RFC 004).
//!
//! Provides clock skew, network partition, and fault injection fixtures.
//! This is an internal testkit crate and is not published.

use std::sync::Arc;
use std::time::Duration;

use opc_session_store::{
    Clock, FakeSessionBackend, FencedSessionReplica, QuorumReplicaDescriptor, QuorumReplicaMember,
    QuorumSessionStore, QuorumTopologyConfig, QuorumTopologyError, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, RestoreBlockReason,
    RestoreBlockReasonCode, TokioVirtualClock, ValidatedQuorumTopology,
};
use opc_types::Timestamp;

/// A SkewableClock wraps a virtual clock and allows injecting positive or negative clock skew.
#[derive(Debug, Clone)]
pub struct SkewableClock {
    base: Arc<TokioVirtualClock>,
    skew: Arc<std::sync::Mutex<ClockSkew>>,
}

#[derive(Debug, Clone, Copy)]
struct ClockSkew {
    duration: Duration,
    negative: bool,
}

impl Default for ClockSkew {
    fn default() -> Self {
        Self {
            duration: Duration::ZERO,
            negative: false,
        }
    }
}

impl SkewableClock {
    pub fn new() -> Self {
        Self {
            base: Arc::new(TokioVirtualClock::new()),
            skew: Arc::new(std::sync::Mutex::new(ClockSkew::default())),
        }
    }

    pub fn with_base(base: Arc<TokioVirtualClock>) -> Self {
        Self {
            base,
            skew: Arc::new(std::sync::Mutex::new(ClockSkew::default())),
        }
    }

    /// Set positive or negative clock skew on this clock.
    pub fn set_skew(&self, skew: Duration, negative: bool) {
        let mut current = self
            .skew
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = ClockSkew {
            duration: skew,
            negative,
        };
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
        let skew = *self
            .skew
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let skewed = apply_clock_skew(*base_ts.as_offset_datetime(), skew);
        // Truncate nanoseconds to 0 to align times across replicas during concurrent operations
        // while preserving exact saturation at the timestamp limits.
        let truncated = if skewed == minimum_utc() || skewed == maximum_utc() {
            skewed
        } else {
            time::OffsetDateTime::from_unix_timestamp(skewed.unix_timestamp()).unwrap_or(skewed)
        };
        Timestamp::from(truncated)
    }
}

fn apply_clock_skew(base: time::OffsetDateTime, skew: ClockSkew) -> time::OffsetDateTime {
    let Ok(delta) = time::Duration::try_from(skew.duration) else {
        return if skew.negative {
            minimum_utc()
        } else {
            maximum_utc()
        };
    };

    if skew.negative {
        base.checked_sub(delta).unwrap_or_else(minimum_utc)
    } else {
        base.checked_add(delta).unwrap_or_else(maximum_utc)
    }
}

fn minimum_utc() -> time::OffsetDateTime {
    time::PrimitiveDateTime::MIN.assume_utc()
}

fn maximum_utc() -> time::OffsetDateTime {
    time::PrimitiveDateTime::MAX.assume_utc()
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
    pub fn build_coordinator(
        &self,
        local_replica_id: usize,
        reached_replica_ids: &[usize],
    ) -> Result<QuorumSessionStore, QuorumTopologyError> {
        let mut view_replicas = Vec::new();
        for replica in &self.replicas {
            let mut wrapped_replica = replica.clone();
            let reached = reached_replica_ids.contains(&replica.id);
            wrapped_replica.client_online = Arc::new(tokio::sync::Mutex::new(reached));
            view_replicas.push(test_member(wrapped_replica)?);
        }
        let topology = build_topology(local_replica_id, view_replicas)?;
        Ok(QuorumSessionStore::from_validated_topology(topology))
    }

    /// Build validated topology for a production-shaped consumer under test.
    pub fn validated_topology(
        &self,
        local_replica_id: usize,
    ) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
        let members = self
            .replicas
            .iter()
            .cloned()
            .map(test_member)
            .collect::<Result<Vec<_>, _>>()?;
        build_topology(local_replica_id, members)
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

fn test_replica_id(index: usize) -> Result<ReplicaId, QuorumTopologyError> {
    ReplicaId::new(format!("chaos-replica-{index}"))
}

fn test_member(replica: FencedSessionReplica) -> Result<QuorumReplicaMember, QuorumTopologyError> {
    let index = replica.id;
    Ok(QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            test_replica_id(index)?,
            ReplicaEndpoint::new(format!("chaos-replica-{index}.invalid"), 7443)?,
            ReplicaTlsIdentity::new(format!("spiffe://test/chaos/replica/{index}"))?,
            ReplicaFailureDomain::new(format!("chaos-failure-domain-{index}"))?,
            ReplicaBackingIdentity::new(format!("chaos-backing-{index}"))?,
        ),
        replica,
    ))
}

fn build_topology(
    local_replica_id: usize,
    members: Vec<QuorumReplicaMember>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(
        test_replica_id(local_replica_id)?,
        members,
    ))
}

/// Fluent assertions for session-store restart and failover restore evidence.
pub struct RestoreEvidenceAsserter<'a> {
    block_reasons: &'a [RestoreBlockReason],
}

impl<'a> RestoreEvidenceAsserter<'a> {
    /// Create an asserter over restore block reasons.
    pub fn new(block_reasons: &'a [RestoreBlockReason]) -> Self {
        Self { block_reasons }
    }

    /// Assert that stale owner/fence writes were rejected during restore.
    pub fn has_stale_owner_rejection(self) -> Self {
        assert!(
            self.block_reasons
                .iter()
                .any(|reason| reason.code == RestoreBlockReasonCode::StaleOwnerRejected),
            "expected stale owner rejection in restore evidence, found: {:?}",
            self.block_reasons
        );
        self
    }

    /// Assert that restore evidence contains a traffic-blocking gate.
    pub fn blocks_traffic_until_restore_complete(self) -> Self {
        assert!(
            self.block_reasons
                .iter()
                .any(RestoreBlockReason::blocks_traffic),
            "expected traffic-blocking restore gate, found: {:?}",
            self.block_reasons
        );
        self
    }

    /// Assert that all restore block messages are marked as traffic safe text.
    pub fn has_redaction_safe_messages(self) -> Self {
        assert!(
            self.block_reasons.iter().all(|reason| {
                !reason.message.contains("192.0.2.")
                    && !reason.message.contains(".db")
                    && !reason.message.contains("/var/")
            }),
            "expected redaction-safe restore messages, found: {:?}",
            self.block_reasons
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_skew_uses_exact_checked_integer_arithmetic() {
        let base = time::OffsetDateTime::UNIX_EPOCH;
        let duration = Duration::new(7, 123_456_789);
        let delta = time::Duration::new(7, 123_456_789);

        assert_eq!(
            apply_clock_skew(
                base,
                ClockSkew {
                    duration,
                    negative: false,
                }
            ),
            base.checked_add(delta)
                .expect("representable positive skew")
        );
        assert_eq!(
            apply_clock_skew(
                base,
                ClockSkew {
                    duration,
                    negative: true,
                }
            ),
            base.checked_sub(delta)
                .expect("representable negative skew")
        );
    }

    #[test]
    fn clock_skew_saturates_at_timestamp_limits() {
        assert_eq!(
            apply_clock_skew(
                maximum_utc(),
                ClockSkew {
                    duration: Duration::from_nanos(1),
                    negative: false,
                }
            ),
            maximum_utc()
        );
        assert_eq!(
            apply_clock_skew(
                minimum_utc(),
                ClockSkew {
                    duration: Duration::from_nanos(1),
                    negative: true,
                }
            ),
            minimum_utc()
        );
        assert_eq!(
            apply_clock_skew(
                time::OffsetDateTime::UNIX_EPOCH,
                ClockSkew {
                    duration: Duration::MAX,
                    negative: false,
                }
            ),
            maximum_utc()
        );
        assert_eq!(
            apply_clock_skew(
                time::OffsetDateTime::UNIX_EPOCH,
                ClockSkew {
                    duration: Duration::MAX,
                    negative: true,
                }
            ),
            minimum_utc()
        );
    }

    #[tokio::test]
    async fn externally_controlled_extreme_skew_cannot_panic() {
        let clock = SkewableClock::new();

        clock.set_skew(Duration::MAX, false);
        assert_eq!(*clock.now_utc().as_offset_datetime(), maximum_utc());

        clock.set_skew(Duration::MAX, true);
        assert_eq!(*clock.now_utc().as_offset_datetime(), minimum_utc());
    }
}
