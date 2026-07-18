//! Chaos and failure testing testkit for OpenPacketCore session replication (RFC 004).
//!
//! Provides clock skew, network partition, and fault injection fixtures.
//! This is an internal testkit crate and is not published.

pub mod qualification;
pub mod qualification_concurrent_v5;
pub mod qualification_kubernetes;
pub mod qualification_kubernetes_campaign;
pub mod qualification_sequential;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::join_all;
use opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE;
use opc_session_store::{
    Clock, ConsensusSessionStore, DurableReadinessState, QuorumReplicaDescriptor,
    QuorumTopologyConfig, QuorumTopologyError, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, RestoreBlockReason,
    RestoreBlockReasonCode, SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SqliteSessionBackend, SystemClock, TokioVirtualClock,
    ValidatedQuorumTopology, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_types::Timestamp;

const CONSENSUS_TEST_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

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

#[derive(Clone)]
struct InProcessConsensusPeer {
    node_id: SessionConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    online: Arc<AtomicBool>,
}

impl InProcessConsensusPeer {
    fn new(node_id: SessionConsensusNodeId) -> Self {
        Self {
            node_id,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            online: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::SeqCst);
    }
}

impl fmt::Debug for InProcessConsensusPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InProcessConsensusPeer")
            .field("node_id", &self.node_id)
            .field("online", &self.online.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for InProcessConsensusPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.online.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

/// A real in-process Openraft fleet for downstream SDK qualification tests.
///
/// Every member owns a distinct file-backed SQLite database. Network faults
/// affect only authenticated consensus RPC paths; no test-only majority or
/// sequencing implementation is involved.
pub struct ConsensusTestCluster {
    _directory: tempfile::TempDir,
    stores: Vec<ConsensusSessionStore>,
    paths: BTreeMap<(usize, usize), Arc<InProcessConsensusPeer>>,
    identity: SessionConsensusIdentity,
}

impl ConsensusTestCluster {
    /// Form a one-member Openraft lab node or a production-shaped HA fleet.
    ///
    /// This internal test helper panics on fixture construction failure so
    /// call sites retain the original failure rather than silently falling
    /// back to a fake coordinator.
    pub async fn start(member_count: usize) -> Self {
        assert!(
            member_count == 1 || member_count >= 3,
            "consensus test fleets require one or at least three members"
        );
        let directory = tempfile::tempdir().expect("create consensus test directory");
        let backends = (0..member_count)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open consensus test SQLite backend")
            })
            .collect::<Vec<_>>();
        let members = (0..member_count)
            .map(|index| test_member(index).expect("build consensus test member descriptor"))
            .collect::<Vec<_>>();
        let cluster_id = opc_consensus::ConsensusClusterId::new("session-consensus-testkit")
            .expect("valid consensus test cluster ID");
        let epoch =
            opc_consensus::ConsensusConfigurationEpoch::new(1).expect("valid consensus test epoch");
        let fingerprints = members
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>();
        let configuration_id =
            opc_consensus::derive_configuration_id(cluster_id, epoch, &fingerprints);
        let identity = opc_consensus::ConsensusIdentity::new(cluster_id, configuration_id, epoch);
        let topologies = (0..member_count)
            .map(|index| {
                if member_count == 1 {
                    ValidatedQuorumTopology::try_new_consensus_lab_singleton(
                        test_replica_id(index).expect("valid consensus test replica ID"),
                        members.clone(),
                        identity,
                    )
                } else {
                    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                        test_replica_id(index).expect("valid consensus test replica ID"),
                        members.clone(),
                        identity,
                    ))
                }
                .expect("validate consensus test topology")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("consensus test node ID")
            })
            .collect::<Vec<_>>();

        let mut paths = BTreeMap::new();
        for source in 0..member_count {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(InProcessConsensusPeer::new(node_id)),
                    );
                }
            }
        }

        let mut stores = Vec::with_capacity(member_count);
        for index in 0..member_count {
            let peers = (0..member_count)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> = paths
                        .get(&(index, target))
                        .expect("consensus test path")
                        .clone();
                    (node_ids[target], peer)
                })
                .collect();
            stores.push(
                ConsensusSessionStore::open_with_clock(
                    topologies[index].clone(),
                    backends[index].clone(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    Arc::new(SystemClock),
                    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .expect("open consensus test node"),
            );
        }

        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }
        for result in join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster)).await {
            result.expect("initialize consensus test fleet");
        }

        let cluster = Self {
            _directory: directory,
            stores,
            paths,
            identity,
        };
        cluster.wait_ready().await;
        cluster
    }

    /// Clone one fleet member's production consensus store adapter.
    pub fn store(&self, index: usize) -> ConsensusSessionStore {
        self.stores
            .get(index)
            .unwrap_or_else(|| panic!("consensus test node {index} does not exist"))
            .clone()
    }

    /// Exact cluster/configuration/epoch scope used by this test fleet.
    pub const fn consensus_identity(&self) -> SessionConsensusIdentity {
        self.identity
    }

    /// Connect or isolate every consensus path to and from one member.
    pub fn set_node_online(&self, index: usize, online: bool) {
        assert!(
            index < self.stores.len(),
            "consensus test node does not exist"
        );
        for ((source, target), path) in &self.paths {
            if *source == index || *target == index {
                path.set_online(online);
            }
        }
    }

    /// Wait until one member proves a fresh linearizable barrier.
    ///
    /// This lets failure tests separate election convergence from the
    /// authoritative operation whose quorum semantics they are asserting.
    pub async fn wait_node_durable_ready(&self, index: usize) {
        let store = self
            .stores
            .get(index)
            .unwrap_or_else(|| panic!("consensus test node {index} does not exist"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if store.probe_durable_readiness().await.is_ready() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "consensus test node did not become durable-ready"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_ready(&self) {
        // Cluster formation can require one resampled election after a split
        // vote and then one complete profiled readiness operation.
        let deadline = tokio::time::Instant::now() + CONSENSUS_TEST_TRANSITION_TIMEOUT;
        loop {
            let reports = join_all(
                self.stores
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            if reports
                .iter()
                .all(|report| report.state() == DurableReadinessState::Ready)
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "consensus test fleet did not become durable-ready"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn test_replica_id(index: usize) -> Result<ReplicaId, QuorumTopologyError> {
    ReplicaId::new(format!("consensus-test-replica-{index}"))
}

fn test_member(index: usize) -> Result<QuorumReplicaDescriptor, QuorumTopologyError> {
    Ok(QuorumReplicaDescriptor::new(
        test_replica_id(index)?,
        ReplicaEndpoint::new(format!("consensus-test-replica-{index}.invalid"), 7443)?,
        ReplicaTlsIdentity::new(format!("spiffe://test/consensus/replica/{index}"))?,
        ReplicaFailureDomain::new(format!("consensus-test-failure-domain-{index}"))?,
        ReplicaBackingIdentity::new(format!("consensus-test-backing-{index}"))?,
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

    #[tokio::test]
    async fn three_node_cluster_forms_from_descriptors_and_consensus_peers() {
        let cluster = ConsensusTestCluster::start(3).await;

        for index in 0..3 {
            let store = cluster.store(index);
            assert_eq!(store.topology().configured_members(), 3);
            assert_eq!(store.topology().required_quorum(), 2);
            assert!(store.probe_durable_readiness().await.is_ready());
        }
    }
}
