//! In-process quorum coordination over a set of session replicas.
//!
//! `QuorumSessionStore` composes replica backends directly in this process and
//! admits HA operation only from an immutable [`ValidatedQuorumTopology`]. The
//! current coordinator derives a majority-visible replication-log prefix and
//! may append its missing suffix to a strict-prefix replica. Conflicts require
//! recovery and are never destructively repaired by readiness. This is
//! prototype behavior, not durable consensus or commit proof; leader/term
//! sequencing and proven repair authority remain required before a production
//! HA claim.
//!
//! The networked transport that exposes a replica over a wire protocol lives
//! in the separate `opc-session-net` crate; from this module's perspective a
//! remote replica is another [`SessionStoreBackend`] implementation paired
//! with validated configured identity.
//!
//! `FencedSessionReplica` wraps each replica with controllable online flags
//! and artificial lag so partition, failover, and split-brain scenarios can
//! be exercised in-process without real networking.

use async_trait::async_trait;
use futures_util::future::join_all;
use futures_util::StreamExt;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{
    next_replication_sequence, validate_replication_page_owned, validate_session_ops_ttls,
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend, SessionOp,
    SessionOpResult,
};
use crate::capability::BackendCapabilities;
use crate::clock::{Clock, SystemClock};
use crate::error::{LeaseError, StoreError};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{FenceToken, OwnerId, SessionKey};
use crate::readiness::{
    DurableReadinessOptions, DurableReadinessReport, DurableReadinessState,
    ReplicaReadinessFailure, ReplicaReadinessObservation, ReplicaReadinessOutcome,
};
use crate::record::StoredSessionRecord;
use crate::restore::{
    compare_restore_records, RestoreScanCursor, RestoreScanPage, RestoreScanRequest,
    RestoreScanScope, RESTORE_SCAN_MAX_PAGE_SIZE,
};
use crate::topology::{
    QuorumReplicaMember, QuorumTopologyMode, QuorumTopologySummary, ReplicaId,
    ValidatedQuorumTopology,
};
use crate::ttl::{checked_session_deadline, validate_session_ttl};
/// Helper trait combining SessionBackend and SessionLeaseManager
pub trait SessionStoreBackend: SessionBackend + SessionLeaseManager {}
impl<T: SessionBackend + SessionLeaseManager> SessionStoreBackend for T {}

/// A wrapper around a session replica node that supports simulated network lag,
/// online/offline states, and epoch/fencing checks.
#[derive(Clone)]
pub struct FencedSessionReplica {
    /// Legacy fault-injection/test-control slot retained for compatibility.
    ///
    /// Validated quorum identity and vote accounting use the member's
    /// [`ReplicaId`], never this number.
    pub id: usize,
    /// The actual backend plus lease manager for this replica — an in-memory
    /// or SQLite backend in tests, or a remote backend from `opc-session-net`
    /// in a distributed deployment.
    pub inner: Arc<dyn SessionStoreBackend>,
    /// Simulates the replica process itself being up. While `false`, every
    /// call through this wrapper fails with `StoreError::BackendUnavailable`,
    /// and the replica stops counting toward quorum.
    pub node_online: Arc<tokio::sync::Mutex<bool>>,
    /// Simulates the network path from this coordinator to the replica.
    /// Toggling it independently of `node_online` models an asymmetric
    /// partition: the replica is healthy but unreachable from here.
    pub client_online: Arc<tokio::sync::Mutex<bool>>,
    /// Optional artificial one-way delay injected before each call, for
    /// exercising slow-replica and replication-lag behavior.
    pub lag: Arc<tokio::sync::Mutex<Option<Duration>>>,
}

impl FencedSessionReplica {
    /// Wrap a backend as replica `id`, initially online with no injected lag.
    pub fn new(id: usize, inner: Arc<dyn SessionStoreBackend>) -> Self {
        Self {
            id,
            inner,
            node_online: Arc::new(tokio::sync::Mutex::new(true)),
            client_online: Arc::new(tokio::sync::Mutex::new(true)),
            lag: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Whether the replica is reachable: both the node itself and the client
    /// network path must be up. Offline replicas are skipped by the
    /// coordinator but still count in the quorum denominator.
    pub async fn is_online(&self) -> bool {
        *self.node_online.lock().await && *self.client_online.lock().await
    }

    /// Simulate the replica process going down (`false`) or recovering
    /// (`true`). A recovered replica is read-repaired to the committed log
    /// prefix before it serves quorum operations again.
    pub async fn set_node_online(&self, online: bool) {
        *self.node_online.lock().await = online;
    }

    /// Simulate losing (`false`) or restoring (`true`) the network path from
    /// the coordinator to this replica, independent of node health.
    pub async fn set_client_online(&self, online: bool) {
        *self.client_online.lock().await = online;
    }

    /// Inject (`Some`) or clear (`None`) an artificial delay applied before
    /// every call to this replica.
    pub async fn set_lag(&self, lag: Option<Duration>) {
        *self.lag.lock().await = lag;
    }

    /// Helper to simulate latency or check offline status.
    async fn check_network(&self) -> Result<(), StoreError> {
        if !self.is_online().await {
            return Err(StoreError::BackendUnavailable(
                "replica offline".to_string(),
            ));
        }
        let lag = *self.lag.lock().await;
        if let Some(dur) = lag {
            tokio::time::sleep(dur).await;
        }
        Ok(())
    }
}

/// In-process replicated quorum session-store adapter over a set of replicas.
///
/// This adapter exercises CAS and lease coordination across a majority of
/// replicas using the current ordered-log and read-repair prototype. A quorum
/// coordinator is composite and deliberately provides no backend-instance
/// identity, so it cannot itself be nested as a voting topology member.
#[derive(Clone)]
pub struct QuorumSessionStore {
    members: Vec<QuorumReplicaMember>,
    topology: QuorumTopologySummary,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
    readiness_options: DurableReadinessOptions,
}

struct ReplicaLogProbe {
    index: usize,
    head: Option<u64>,
    log: Option<Vec<ReplicationEntry>>,
    failure: Option<ReplicaReadinessFailure>,
}

impl ReplicaLogProbe {
    fn failed(index: usize, head: Option<u64>, failure: ReplicaReadinessFailure) -> Self {
        Self {
            index,
            head,
            log: None,
            failure: Some(failure),
        }
    }

    fn complete(index: usize, head: u64, log: Vec<ReplicationEntry>) -> Self {
        Self {
            index,
            head: Some(head),
            log: Some(log),
            failure: None,
        }
    }
}

struct QuorumAssessment {
    report: DurableReadinessReport,
    ready_indices: Vec<usize>,
    majority_visible_prefix: Vec<ReplicationEntry>,
}

const DURABLE_READINESS_LOG_PAGE_ENTRIES: usize = 16;

impl QuorumSessionStore {
    /// Build an operational coordinator from topology that already passed HA
    /// or explicit lab-singleton admission.
    ///
    /// The quorum denominator is the validated immutable configured membership,
    /// not the set of currently reachable backends.
    pub fn from_validated_topology(topology: ValidatedQuorumTopology) -> Self {
        let (topology, members) = topology.into_parts();
        Self::build(topology, members)
    }

    /// Build a non-operational coordinator from a raw positional vector.
    ///
    /// This compatibility constructor retains the old source shape, but the
    /// resulting store advertises an unknown platform profile and every store
    /// operation fails closed. Migrate to [`Self::from_validated_topology`], or
    /// to [`ValidatedQuorumTopology::try_new_lab_singleton`] for an explicit
    /// one-replica lab.
    #[deprecated(
        note = "raw replica vectors are non-operational; construct a ValidatedQuorumTopology"
    )]
    pub fn new(replicas: Vec<FencedSessionReplica>) -> Self {
        let configured_members = replicas.len();
        let members = replicas
            .into_iter()
            .enumerate()
            .map(|(index, replica)| {
                QuorumReplicaMember::new(
                    crate::topology::QuorumReplicaDescriptor::unvalidated_legacy(index),
                    replica,
                )
            })
            .collect();
        Self::build(
            QuorumTopologySummary::unvalidated_legacy(configured_members),
            members,
        )
    }

    fn build(topology: QuorumTopologySummary, members: Vec<QuorumReplicaMember>) -> Self {
        let caps = BackendCapabilities {
            atomic_compare_and_set: true,
            monotonic_fencing_token: true,
            per_key_ttl: true,
            server_side_lease_expiry: true,
            ordered_replication_log: true,
            batch_write: true,
            watch: true,
            restore_scan: true,
            max_value_bytes: usize::MAX,
        };
        Self {
            members,
            topology,
            caps,
            clock: Arc::new(SystemClock),
            readiness_options: DurableReadinessOptions::default(),
        }
    }

    /// Redaction-safe immutable topology summary.
    pub fn topology(&self) -> &QuorumTopologySummary {
        &self.topology
    }

    /// Platform profile this admitted topology is permitted to advertise.
    pub const fn platform_profile(&self) -> crate::capability::SessionStorePlatformProfile {
        self.topology.mode().platform_profile()
    }

    /// Replace the clock used to timestamp replication entries and to compute
    /// lease `expires_at` deadlines — pair it with the replicas' clocks (e.g.
    /// a shared `TokioVirtualClock`) so lease-expiry tests are deterministic.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Configure the single bounded readiness policy shared by explicit
    /// probes and all authoritative operations.
    ///
    /// Keeping one store-level policy prevents a probe from succeeding under
    /// looser limits than the operation it is intended to gate.
    pub fn with_durable_readiness_options(mut self, options: DurableReadinessOptions) -> Self {
        self.readiness_options = options;
        self
    }

    /// Return the bounded policy used by probes and authoritative operations.
    pub const fn durable_readiness_options(&self) -> DurableReadinessOptions {
        self.readiness_options
    }

    fn quorum_size(&self) -> usize {
        self.topology.required_quorum()
    }

    fn ensure_operational_topology(&self) -> Result<(), StoreError> {
        if self.topology.mode() == QuorumTopologyMode::UnvalidatedLegacy {
            return Err(StoreError::BackendUnavailable(
                "session-store topology is not validated".into(),
            ));
        }
        Ok(())
    }

    fn replica(&self, index: usize) -> &FencedSessionReplica {
        self.members[index].replica()
    }

    fn replica_id(&self, index: usize) -> &ReplicaId {
        self.members[index].descriptor().replica_id()
    }

    async fn collect_replica_log(
        &self,
        index: usize,
        deadline: tokio::time::Instant,
        max_log_entries: usize,
    ) -> ReplicaLogProbe {
        let replica = self.replica(index);
        match tokio::time::timeout_at(deadline, replica.check_network()).await {
            Err(_) => {
                return ReplicaLogProbe::failed(index, None, ReplicaReadinessFailure::Timeout)
            }
            Ok(Err(_)) => {
                return ReplicaLogProbe::failed(index, None, ReplicaReadinessFailure::Transport)
            }
            Ok(Ok(())) => {}
        }

        let head =
            match tokio::time::timeout_at(deadline, replica.inner.probe_replication_head()).await {
                Err(_) => {
                    return ReplicaLogProbe::failed(index, None, ReplicaReadinessFailure::Timeout)
                }
                Ok(Err(failure)) => return ReplicaLogProbe::failed(index, None, failure),
                Ok(Ok(head)) => head,
            };

        let limit = match usize::try_from(head) {
            Ok(limit) if limit <= max_log_entries => limit,
            _ => {
                return ReplicaLogProbe::failed(
                    index,
                    Some(head),
                    ReplicaReadinessFailure::ProbeBudgetExceeded,
                )
            }
        };
        let log = match self.load_replica_log_pages(index, limit, deadline).await {
            Ok(log) => log,
            Err(failure) => return ReplicaLogProbe::failed(index, Some(head), failure),
        };

        ReplicaLogProbe::complete(index, head, log)
    }

    async fn load_replica_log_pages(
        &self,
        index: usize,
        expected_entries: usize,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<ReplicationEntry>, ReplicaReadinessFailure> {
        let replica = self.replica(index);
        let mut entries = Vec::new();
        let mut page_limit = DURABLE_READINESS_LOG_PAGE_ENTRIES.min(expected_entries);

        while entries.len() < expected_entries {
            let remaining = expected_entries - entries.len();
            let request_limit = page_limit.min(remaining);
            let start = u64::try_from(entries.len())
                .ok()
                .and_then(|offset| offset.checked_add(1))
                .ok_or(ReplicaReadinessFailure::ProbeBudgetExceeded)?;
            let page = match tokio::time::timeout_at(
                deadline,
                replica.inner.get_replication_log(start, request_limit),
            )
            .await
            {
                Err(_) => return Err(ReplicaReadinessFailure::Timeout),
                Ok(Err(_)) if request_limit > 1 => {
                    page_limit = (request_limit / 2).max(1);
                    continue;
                }
                Ok(Err(_)) => return Err(ReplicaReadinessFailure::LogUnavailable),
                Ok(Ok(page)) => match validate_replication_page_owned(page) {
                    Ok(page) => page,
                    Err(_) => return Err(ReplicaReadinessFailure::Divergent),
                },
            };

            if page.is_empty() || page.len() > request_limit {
                return Err(ReplicaReadinessFailure::Divergent);
            }
            let page_is_contiguous = page.iter().enumerate().all(|(offset, entry)| {
                u64::try_from(offset)
                    .ok()
                    .and_then(|offset| start.checked_add(offset))
                    == Some(entry.sequence)
            });
            if !page_is_contiguous {
                return Err(ReplicaReadinessFailure::Divergent);
            }
            entries.extend(page);
        }

        Ok(entries)
    }

    fn majority_visible_prefix(probes: &[ReplicaLogProbe], quorum: usize) -> Vec<ReplicationEntry> {
        let logs = probes
            .iter()
            .filter_map(|probe| probe.log.as_ref())
            .collect::<Vec<_>>();
        let mut supporters = (0..logs.len()).collect::<Vec<_>>();
        let mut prefix = Vec::new();

        loop {
            let position = prefix.len();
            let mut groups: Vec<(&ReplicationEntry, Vec<usize>)> = Vec::new();
            for supporter in supporters.iter().copied() {
                let Some(entry) = logs[supporter].get(position) else {
                    continue;
                };
                if let Some((_, voters)) =
                    groups.iter_mut().find(|(candidate, _)| *candidate == entry)
                {
                    voters.push(supporter);
                } else {
                    groups.push((entry, vec![supporter]));
                }
            }

            let Some((entry, next_supporters)) = groups
                .into_iter()
                .find(|(_, voters)| voters.len() >= quorum)
            else {
                break;
            };
            prefix.push(entry.clone());
            supporters = next_supporters;
        }

        prefix
    }

    async fn assess_durable_readiness(&self, options: DurableReadinessOptions) -> QuorumAssessment {
        let configured_voters = self.members.len();
        let required_quorum = self.quorum_size();
        if self.topology.mode() == QuorumTopologyMode::UnvalidatedLegacy {
            return QuorumAssessment {
                report: DurableReadinessReport::new(
                    DurableReadinessState::TopologyInvalid,
                    configured_voters,
                    0,
                    0,
                    required_quorum,
                    None,
                    Vec::new(),
                ),
                ready_indices: Vec::new(),
                majority_visible_prefix: Vec::new(),
            };
        }

        let deadline = tokio::time::Instant::now() + options.timeout();
        let probes = join_all(
            (0..configured_voters)
                .map(|index| self.collect_replica_log(index, deadline, options.max_log_entries())),
        )
        .await;
        let fresh_reachable_voters = probes.iter().filter(|probe| probe.head.is_some()).count();
        let usable_voters = probes.iter().filter(|probe| probe.log.is_some()).count();

        let mut observations = probes
            .iter()
            .map(|probe| {
                ReplicaReadinessObservation::new(
                    self.replica_id(probe.index).clone(),
                    probe.head,
                    probe
                        .failure
                        .map(ReplicaReadinessOutcome::Failed)
                        .unwrap_or(ReplicaReadinessOutcome::Fresh),
                )
            })
            .collect::<Vec<_>>();

        if usable_voters < required_quorum {
            let recovery_required = probes
                .iter()
                .any(|probe| probe.failure == Some(ReplicaReadinessFailure::Divergent));
            return QuorumAssessment {
                report: DurableReadinessReport::new(
                    if recovery_required {
                        DurableReadinessState::RecoveryRequired
                    } else {
                        DurableReadinessState::NoQuorum
                    },
                    configured_voters,
                    fresh_reachable_voters,
                    0,
                    required_quorum,
                    None,
                    observations,
                ),
                ready_indices: Vec::new(),
                majority_visible_prefix: Vec::new(),
            };
        }

        let prefix = Self::majority_visible_prefix(&probes, required_quorum);
        let prefix_index = u64::try_from(prefix.len()).unwrap_or(u64::MAX);
        let mut ready_indices = Vec::new();
        let mut repair_candidates = Vec::new();
        let mut recovery_required = probes.iter().any(|probe| {
            probe.failure == Some(ReplicaReadinessFailure::Divergent)
                || (probe.log.is_none()
                    && probe
                        .head
                        .is_some_and(|observed_head| observed_head > prefix_index))
        });

        for probe in &probes {
            let Some(log) = probe.log.as_ref() else {
                continue;
            };
            let shared_len = log.len().min(prefix.len());
            if log[..shared_len] != prefix[..shared_len] || log.len() > prefix.len() {
                observations[probe.index] = ReplicaReadinessObservation::new(
                    self.replica_id(probe.index).clone(),
                    probe.head,
                    ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Divergent),
                );
                recovery_required = true;
            } else if log.len() == prefix.len() {
                observations[probe.index] = ReplicaReadinessObservation::new(
                    self.replica_id(probe.index).clone(),
                    probe.head,
                    ReplicaReadinessOutcome::Ready,
                );
                ready_indices.push(probe.index);
            } else {
                repair_candidates.push((probe.index, log.len()));
            }
        }

        let repair_results = if recovery_required {
            Vec::new()
        } else {
            join_all(repair_candidates.into_iter().map(|(index, start)| {
                let missing = &prefix[start..];
                async move {
                    opc_redaction::metrics::METRICS
                        .session_replica_repair
                        .fetch_add(1, Ordering::Relaxed);
                    for entry in missing.iter().cloned() {
                        match tokio::time::timeout_at(
                            deadline,
                            self.replica(index).inner.replicate_entry(entry),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => return (index, false),
                        }
                    }
                    opc_redaction::metrics::METRICS
                        .session_replica_catchup
                        .fetch_add(1, Ordering::Relaxed);
                    (index, true)
                }
            }))
            .await
        };

        for (index, repaired) in repair_results {
            if repaired {
                observations[index] = ReplicaReadinessObservation::new(
                    self.replica_id(index).clone(),
                    Some(u64::try_from(prefix.len()).unwrap_or(u64::MAX)),
                    ReplicaReadinessOutcome::Repaired,
                );
                ready_indices.push(index);
            } else {
                observations[index] = ReplicaReadinessObservation::new(
                    self.replica_id(index).clone(),
                    probes[index].head,
                    ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::RepairFailed),
                );
            }
        }

        let agreeing_voters = ready_indices.len();
        let state = if recovery_required {
            DurableReadinessState::RecoveryRequired
        } else if agreeing_voters >= required_quorum {
            DurableReadinessState::Ready
        } else {
            DurableReadinessState::NoQuorum
        };
        QuorumAssessment {
            report: DurableReadinessReport::new(
                state,
                configured_voters,
                fresh_reachable_voters,
                agreeing_voters,
                required_quorum,
                Some(prefix_index),
                observations,
            ),
            ready_indices,
            majority_visible_prefix: prefix,
        }
    }

    fn record_readiness_metrics(report: &DurableReadinessReport) {
        let metrics = &opc_redaction::metrics::METRICS;
        let usize_to_u64 = |value| u64::try_from(value).unwrap_or(u64::MAX);
        metrics
            .session_durable_readiness_ready
            .store(if report.is_ready() { 1 } else { 0 }, Ordering::Relaxed);
        metrics
            .session_durable_readiness_configured_voters
            .store(usize_to_u64(report.configured_voters()), Ordering::Relaxed);
        metrics
            .session_durable_readiness_fresh_reachable_voters
            .store(
                usize_to_u64(report.fresh_reachable_voters()),
                Ordering::Relaxed,
            );
        metrics
            .session_durable_readiness_agreeing_voters
            .store(usize_to_u64(report.agreeing_voters()), Ordering::Relaxed);
        metrics
            .session_durable_readiness_required_quorum
            .store(usize_to_u64(report.required_quorum()), Ordering::Relaxed);
        metrics
            .session_durable_readiness_majority_visible_prefix
            .store(
                report.majority_visible_prefix_index().unwrap_or(0),
                Ordering::Relaxed,
            );

        if report.is_ready() {
            metrics
                .session_durable_readiness_probe_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            metrics
                .session_durable_readiness_probe_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        if report.state() == DurableReadinessState::RecoveryRequired {
            metrics
                .session_durable_readiness_recovery_required_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        for observation in report.replica_observations() {
            match observation.outcome() {
                ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Timeout) => {
                    metrics
                        .session_durable_readiness_timeout_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Authentication) => {
                    metrics
                        .session_durable_readiness_authentication_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Transport) => {
                    metrics
                        .session_durable_readiness_transport_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Divergent) => {
                    metrics
                        .session_durable_readiness_divergent_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    /// Perform a fresh, bounded assessment of distinct replica reachability,
    /// majority-prefix agreement, and safe strict-prefix catch-up.
    ///
    /// Cached capabilities are never consulted. The result is point-in-time
    /// evidence only; every authoritative operation repeats this same
    /// fail-closed assessment.
    pub async fn probe_durable_readiness(&self) -> DurableReadinessReport {
        let assessment = self.assess_durable_readiness(self.readiness_options).await;
        Self::record_readiness_metrics(&assessment.report);
        assessment.report
    }

    async fn committed_and_repaired(
        &self,
    ) -> Result<(Vec<usize>, Vec<ReplicationEntry>), StoreError> {
        let assessment = self.assess_durable_readiness(self.readiness_options).await;
        match assessment.report.state() {
            DurableReadinessState::Ready => {
                Ok((assessment.ready_indices, assessment.majority_visible_prefix))
            }
            DurableReadinessState::TopologyInvalid => Err(StoreError::BackendUnavailable(
                "session-store topology is not validated".into(),
            )),
            DurableReadinessState::NoQuorum => Err(StoreError::BackendUnavailable(
                "durable session-store quorum not ready".into(),
            )),
            DurableReadinessState::RecoveryRequired => Err(StoreError::BackendUnavailable(
                "durable session-store recovery required".into(),
            )),
        }
    }

    async fn replicate_mutation(&self, op: ReplicationOp) -> Result<(), StoreError> {
        let timestamp = self.clock.now_utc();
        op.validate_ttls_at(timestamp)?;
        let (online_ids, committed_entries) = self.committed_and_repaired().await?;
        let quorum = self.quorum_size();
        let committed_sequence = committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0);
        let next_seq = next_replication_sequence(committed_sequence)?;
        let tx_id = uuid::Uuid::new_v4().to_string();
        let entry = ReplicationEntry {
            sequence: next_seq,
            tx_id,
            op,
            timestamp,
        };

        let mut successful_voters = HashSet::new();
        let mut successful_ids = Vec::new();
        let mut last_err = None;
        for id in &online_ids {
            let replica = self.replica(*id);
            match replica.inner.replicate_entry(entry.clone()).await {
                Ok(()) => {
                    successful_voters.insert(self.replica_id(*id).clone());
                    successful_ids.push(*id);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if successful_voters.len() >= quorum {
            opc_redaction::metrics::METRICS
                .session_quorum_write_success
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_committed_replication_sequence
                .store(entry.sequence, Ordering::Relaxed);
            Ok(())
        } else {
            opc_redaction::metrics::METRICS
                .session_quorum_write_failure
                .fetch_add(1, Ordering::Relaxed);
            for id in successful_ids {
                opc_redaction::metrics::METRICS
                    .session_failed_partial_write_rollback
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .replica(id)
                    .inner
                    .rebuild_replication_state(committed_entries.clone())
                    .await;
            }
            if let Some(err) = last_err {
                Err(err)
            } else {
                Err(StoreError::BackendUnavailable(
                    "quorum not reached for replication".into(),
                ))
            }
        }
    }

    pub(crate) async fn get_inner(
        &self,
        key: &SessionKey,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let (online_ids, _) = self.committed_and_repaired().await?;
        let quorum = self.quorum_size();

        // Query all online replicas and count occurrences of each result
        let mut results: Vec<(ReplicaId, Option<StoredSessionRecord>)> = Vec::new();
        for id in &online_ids {
            let replica = self.replica(*id);
            if let Ok(rec) = replica.inner.get(key).await {
                results.push((self.replica_id(*id).clone(), rec));
            }
        }

        // Find the majority consensus
        let mut consensus_val = None;
        let mut consensus_found = false;

        for (_, candidate) in &results {
            let mut voters = HashSet::new();
            for (replica_id, result) in &results {
                match (candidate, result) {
                    (None, None) => {
                        voters.insert(replica_id.clone());
                    }
                    (Some(c), Some(x))
                        if c.generation == x.generation
                            && c.owner == x.owner
                            && c.fence == x.fence
                            && c.state_class == x.state_class
                            && c.state_type == x.state_type
                            && c.expires_at == x.expires_at
                            && c.payload == x.payload =>
                    {
                        voters.insert(replica_id.clone());
                    }
                    _ => {}
                }
            }
            if voters.len() >= quorum {
                consensus_val = candidate.clone();
                consensus_found = true;
                break;
            }
        }

        if consensus_found {
            Ok(consensus_val)
        } else {
            Err(StoreError::BackendUnavailable(
                "no quorum consensus for session record".into(),
            ))
        }
    }

    pub(crate) async fn watch_inner(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let (ready_ids, _) = self.committed_and_repaired().await?;
        for id in ready_ids {
            if let Ok(stream) = self.replica(id).inner.watch(start_sequence).await {
                return Ok(stream
                    .map(|result| result.and_then(ReplicationEntry::into_validated))
                    .boxed());
            }
        }
        Err(StoreError::BackendUnavailable(
            "no caught-up replica available for watch".into(),
        ))
    }

    async fn scan_replica_restore_records(
        replica: &FencedSessionReplica,
    ) -> Result<Vec<StoredSessionRecord>, StoreError> {
        let mut cursor = None;
        let mut records = Vec::new();

        loop {
            let page = replica
                .inner
                .scan_restore_records(RestoreScanRequest {
                    scope: RestoreScanScope::all(),
                    cursor,
                    limit: RESTORE_SCAN_MAX_PAGE_SIZE,
                })
                .await?;
            let next_cursor = page.next_cursor;
            records.extend(page.records);

            if page.complete {
                return Ok(records);
            }

            let Some(next_cursor) = next_cursor else {
                return Err(StoreError::BackendUnavailable(
                    "restore scan page omitted next cursor".into(),
                ));
            };
            if cursor == Some(next_cursor) {
                return Err(StoreError::BackendUnavailable(
                    "restore scan cursor did not advance".into(),
                ));
            }
            cursor = Some(next_cursor);
        }
    }

    fn merge_restore_scan_record(
        merged: &mut HashMap<SessionKey, StoredSessionRecord>,
        record: StoredSessionRecord,
    ) {
        merged
            .entry(record.key.clone())
            .and_modify(|existing| {
                if record.generation > existing.generation {
                    *existing = record.clone();
                }
            })
            .or_insert(record);
    }
}

#[async_trait]
impl SessionBackend for QuorumSessionStore {
    async fn capabilities(&self) -> BackendCapabilities {
        if self.topology.mode() == QuorumTopologyMode::UnvalidatedLegacy {
            return BackendCapabilities::minimal();
        }
        let mut caps = self.caps;

        for member in &self.members {
            let replica = member.replica();
            let replica_caps = replica.inner.capabilities().await;
            caps.atomic_compare_and_set &= replica_caps.atomic_compare_and_set;
            caps.monotonic_fencing_token &= replica_caps.monotonic_fencing_token;
            caps.per_key_ttl &= replica_caps.per_key_ttl;
            caps.server_side_lease_expiry &= replica_caps.server_side_lease_expiry;
            caps.batch_write &= replica_caps.batch_write;
            caps.restore_scan &= replica_caps.restore_scan;
            caps.max_value_bytes = caps.max_value_bytes.min(replica_caps.max_value_bytes);
        }

        caps
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let res = self.get_inner(key).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_quorum_read_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .session_quorum_read_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let op_clone = ReplicationOp::CompareAndSet {
            key: op.key.clone(),
            expected_generation: op.expected_generation,
            credential_id: op.lease.credential_id(),
            guard_expires_at: op.lease.expires_at(),
            new_record: op.new_record,
        };
        match self.replicate_mutation(op_clone).await {
            Ok(()) => Ok(CompareAndSetResult::Success),
            Err(StoreError::CasConflict) => {
                let current = self.get(op.lease.key()).await.unwrap_or(None);
                Ok(CompareAndSetResult::Conflict { current })
            }
            Err(e) => Err(e),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let op = ReplicationOp::DeleteFenced {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
        };
        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_delete
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        checked_session_deadline(self.clock.now_utc(), ttl)?;
        self.ensure_operational_topology()?;
        let now = self.clock.now_utc();
        let expires_at = checked_session_deadline(now, ttl)?;
        let op = ReplicationOp::RefreshTtl {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            ttl,
            expires_at,
        };
        self.replicate_mutation(op).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        validate_session_ops_ttls(&ops)?;
        let validation_now = self.clock.now_utc();
        for op in &ops {
            if let SessionOp::RefreshTtl { ttl, .. } = op {
                checked_session_deadline(validation_now, *ttl)?;
            }
        }
        self.ensure_operational_topology()?;
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let result = match op {
                SessionOp::Get { key } => SessionOpResult::Get(self.get(&key).await),
                SessionOp::CompareAndSet(cas) => {
                    SessionOpResult::CompareAndSet(self.compare_and_set(cas).await)
                }
                SessionOp::DeleteFenced { lease } => {
                    SessionOpResult::DeleteFenced(self.delete_fenced(&lease).await)
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    SessionOpResult::RefreshTtl(self.refresh_ttl(&lease, ttl).await)
                }
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;

        let (online_ids, _) = self.committed_and_repaired().await?;
        let quorum = self.quorum_size();
        let mut successful_scans = HashSet::new();
        let mut last_err = None;
        let mut merged = HashMap::new();

        for id in online_ids {
            let replica = self.replica(id);
            match Self::scan_replica_restore_records(replica).await {
                Ok(records) => {
                    successful_scans.insert(self.replica_id(id).clone());
                    for record in records {
                        Self::merge_restore_scan_record(&mut merged, record);
                    }
                }
                Err(StoreError::CapabilityNotSupported(capability))
                    if capability == "restore_scan" => {}
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }

        if successful_scans.len() < quorum {
            return Err(last_err.unwrap_or_else(|| {
                StoreError::BackendUnavailable("quorum not reached for restore scan".into())
            }));
        }

        let mut matching = Vec::new();
        let mut excluded_count = 0;
        for record in merged.into_values() {
            if request.scope.matches_record(&record) {
                matching.push(record);
            } else {
                excluded_count += 1;
            }
        }
        matching.sort_by(compare_restore_records);

        let start = request
            .cursor
            .map(RestoreScanCursor::offset)
            .unwrap_or(0)
            .min(matching.len());
        let end = start.saturating_add(request.limit).min(matching.len());
        let next_cursor = (end < matching.len()).then(|| RestoreScanCursor::from_offset(end));
        let records = matching[start..end].to_vec();

        Ok(RestoreScanPage::new(records, excluded_count, next_cursor))
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let (_, committed_entries) = self.committed_and_repaired().await?;
        Ok(committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0))
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let (_, committed_entries) = self.committed_and_repaired().await?;
        let entries = committed_entries
            .into_iter()
            .filter(|entry| entry.sequence >= start)
            .take(limit)
            .collect::<Vec<_>>();
        validate_replication_page_owned(entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        let (online_ids, committed_entries) = self.committed_and_repaired().await?;
        let committed_seq = committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0);

        if entry.sequence <= committed_seq {
            let committed_entry = committed_entries
                .iter()
                .find(|committed| committed.sequence == entry.sequence)
                .ok_or_else(|| {
                    StoreError::BackendUnavailable("replication log sequence gap".into())
                })?;
            if committed_entry == &entry {
                return Ok(());
            }
            return Err(StoreError::BackendUnavailable(
                "divergent committed replication entry".into(),
            ));
        }

        if entry.sequence != next_replication_sequence(committed_seq)? {
            return Err(StoreError::BackendUnavailable(
                "replication log sequence gap".into(),
            ));
        }

        let mut successful_voters = HashSet::new();
        let mut successful_ids = Vec::new();
        let mut last_err = None;
        for id in online_ids {
            let replica = self.replica(id);
            match replica.inner.replicate_entry(entry.clone()).await {
                Ok(()) => {
                    successful_voters.insert(self.replica_id(id).clone());
                    successful_ids.push(id);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if successful_voters.len() >= self.quorum_size() {
            opc_redaction::metrics::METRICS
                .session_committed_replication_sequence
                .store(entry.sequence, Ordering::Relaxed);
            Ok(())
        } else {
            for id in successful_ids {
                opc_redaction::metrics::METRICS
                    .session_failed_partial_write_rollback
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .replica(id)
                    .inner
                    .rebuild_replication_state(committed_entries.clone())
                    .await;
            }
            if let Some(err) = last_err {
                Err(err)
            } else {
                Err(StoreError::BackendUnavailable("quorum not reached".into()))
            }
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let res = self.watch_inner(start_sequence).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_watch_resume_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .session_watch_resume_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

#[async_trait]
impl SessionLeaseManager for QuorumSessionStore {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        let (online_ids, _) = self
            .committed_and_repaired()
            .await
            .map_err(|e| LeaseError::Backend(e.to_string()))?;

        let mut max_fence = 0;
        let mut max_cred_id = 0;
        let mut sequencing_voters = HashSet::new();
        let sequencing_results = join_all(
            online_ids
                .iter()
                .copied()
                .map(|id| async move { (id, self.replica(id).inner.next_lease_info().await) }),
        )
        .await;
        for (id, result) in sequencing_results {
            if let Ok((fence, credential_id)) = result {
                sequencing_voters.insert(self.replica_id(id).clone());
                max_fence = max_fence.max(fence);
                max_cred_id = max_cred_id.max(credential_id);
            }
        }
        if sequencing_voters.len() < self.quorum_size() {
            return Err(LeaseError::Backend(
                "quorum not reached for lease_coordination".into(),
            ));
        }

        let fence = FenceToken::new(max_fence);
        let credential_id = max_cred_id;
        let now = self.clock.now_utc();
        let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;

        let op = ReplicationOp::AcquireLease {
            key: key.clone(),
            owner: owner.clone(),
            fence,
            credential_id,
            ttl,
            expires_at,
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_acquire
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)?;

        Ok(LeaseGuard::new(
            key.clone(),
            owner,
            fence,
            now,
            expires_at,
            credential_id,
        ))
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        self.ensure_operational_topology()
            .map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let op = ReplicationOp::RenewLease {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            credential_id: lease.credential_id(),
            ttl,
            expires_at,
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_renew
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)?;

        Ok(LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            now,
            expires_at,
            lease.credential_id(),
        ))
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let op = ReplicationOp::ReleaseLease {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            credential_id: lease.credential_id(),
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_release
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_replication_sequence_reports_overflow() {
        let entry = ReplicationEntry {
            sequence: u64::MAX,
            tx_id: "max-sequence".into(),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: opc_types::Timestamp::now_utc(),
        };

        let err =
            next_replication_sequence(entry.sequence).expect_err("sequence overflow must error");
        assert_eq!(
            err,
            StoreError::BackendUnavailable("replication sequence exhausted".into())
        );
    }
}
