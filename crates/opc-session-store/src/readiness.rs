//! Fresh, bounded durable-readiness evidence for replicated session stores.
//!
//! Capability declarations and validated topology are admission evidence. They
//! do not prove that Openraft can complete a linearizable barrier now. The
//! types in this module deliberately expose only stable reason codes, counts,
//! committed-barrier indexes, and redaction-safe replica identities.

use crate::topology::ReplicaId;

/// Local Openraft recovery posture observed during a durable-readiness probe.
///
/// This is deliberately lower-cardinality than Openraft's internal metrics.
/// It exposes only whether the local durable replica is synchronized, applying
/// authoritative state, waiting for quorum, or requires operator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DurableRecoveryState {
    /// The local state machine applied through the successful committed
    /// barrier returned by Openraft.
    Synchronized,
    /// The local durable log is ahead of the applied state machine and
    /// Openraft is responsible for completing catch-up.
    CatchingUp,
    /// No authoritative barrier completed; no destructive repair was run.
    AwaitingQuorum,
    /// Openraft stopped fatally or durable state failed closed and requires
    /// operator recovery.
    RecoveryRequired,
}

impl DurableRecoveryState {
    /// Stable low-cardinality code suitable for health and metrics surfaces.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Synchronized => "synchronized",
            Self::CatchingUp => "catching_up",
            Self::AwaitingQuorum => "awaiting_quorum",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

/// Redaction-safe local progress for Openraft-owned recovery.
///
/// Indexes are operational counters, not session identifiers. The report does
/// not expose terms, node IDs, endpoints, payloads, transaction IDs, or
/// Openraft error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableRecoveryProgress {
    state: DurableRecoveryState,
    local_log_index: Option<u64>,
    local_applied_index: Option<u64>,
    snapshot_index: Option<u64>,
    purged_index: Option<u64>,
}

impl DurableRecoveryProgress {
    pub(crate) const fn new(
        state: DurableRecoveryState,
        local_log_index: Option<u64>,
        local_applied_index: Option<u64>,
        snapshot_index: Option<u64>,
        purged_index: Option<u64>,
    ) -> Self {
        Self {
            state,
            local_log_index,
            local_applied_index,
            snapshot_index,
            purged_index,
        }
    }

    /// Typed recovery posture.
    pub const fn state(self) -> DurableRecoveryState {
        self.state
    }

    /// Stable low-cardinality recovery code.
    pub const fn reason_code(self) -> &'static str {
        self.state.reason_code()
    }

    /// Last local Openraft log index, when one remains after compaction.
    pub const fn local_log_index(self) -> Option<u64> {
        self.local_log_index
    }

    /// Last locally applied Openraft log index.
    pub const fn local_applied_index(self) -> Option<u64> {
        self.local_applied_index
    }

    /// Last index represented by the current local snapshot.
    pub const fn snapshot_index(self) -> Option<u64> {
        self.snapshot_index
    }

    /// Last index durably purged after snapshot compaction.
    pub const fn purged_index(self) -> Option<u64> {
        self.purged_index
    }
}

/// Point-in-time result of a fresh durable-readiness assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DurableReadinessState {
    /// Openraft completed a linearizable barrier and local apply wait against
    /// the admitted voting configuration.
    Ready,
    /// Openraft could not complete the barrier before the operation deadline.
    NoQuorum,
    /// The coordinator was not built from an admitted topology, or production
    /// topology evidence was absent, non-production, not yet valid, expired, or
    /// bound to another immutable configuration.
    TopologyInvalid,
    /// Conflicting or unrepairable durable state requires recovery action.
    RecoveryRequired,
}

impl DurableReadinessState {
    /// Stable low-cardinality status code suitable for health responses.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoQuorum => "no_quorum",
            Self::TopologyInvalid => "topology_invalid",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

/// Authority scope carried by a durable-readiness report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DurableReadinessScope {
    /// Openraft engine evidence without authenticated platform topology.
    EngineOnly,
    /// Result produced by the gate that requires production platform
    /// attestation, including a typed failure from that gate.
    ProductionTopologyAttested,
}

impl DurableReadinessScope {
    /// Stable low-cardinality scope code suitable for health responses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngineOnly => "engine-only",
            Self::ProductionTopologyAttested => "production-topology-attested",
        }
    }
}

/// Typed, redaction-safe reason one configured replica did not contribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplicaReadinessFailure {
    /// The configured network path could not be established or was lost.
    Transport,
    /// Peer authentication or TLS verification failed.
    Authentication,
    /// The bounded request or overall assessment deadline elapsed.
    Timeout,
    /// The peer violated or did not support the wire contract.
    Protocol,
    /// The peer returned a backend operation failure.
    Backend,
    /// A fresh head was observed but its ordered log could not be loaded.
    LogUnavailable,
    /// Legacy compatibility code observed a divergent application log.
    Divergent,
    /// Legacy compatibility repair failed.
    RepairFailed,
    /// The bounded replication-log work budget was exceeded.
    ProbeBudgetExceeded,
}

impl ReplicaReadinessFailure {
    /// Stable low-cardinality failure code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Authentication => "authentication",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Backend => "backend",
            Self::LogUnavailable => "log_unavailable",
            Self::Divergent => "divergent",
            Self::RepairFailed => "repair_failed",
            Self::ProbeBudgetExceeded => "probe_budget_exceeded",
        }
    }
}

/// Result contributed by one configured voter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplicaReadinessOutcome {
    /// The local Openraft state machine applied through the fresh linearizable
    /// barrier, or a compatibility adapter supplied fresh evidence.
    Fresh,
    /// A compatibility adapter's replica matched its admitted authority.
    Ready,
    /// A compatibility adapter repaired a stale replica.
    Repaired,
    /// The replica could not contribute usable evidence.
    Failed(ReplicaReadinessFailure),
}

/// Redaction-safe point-in-time observation for one configured voter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaReadinessObservation {
    replica_id: ReplicaId,
    observed_sequence: Option<u64>,
    outcome: ReplicaReadinessOutcome,
}

impl ReplicaReadinessObservation {
    pub(crate) fn new(
        replica_id: ReplicaId,
        observed_sequence: Option<u64>,
        outcome: ReplicaReadinessOutcome,
    ) -> Self {
        Self {
            replica_id,
            observed_sequence,
            outcome,
        }
    }

    /// Configured logical identity. Its `Debug` representation is redacted.
    pub const fn replica_id(&self) -> &ReplicaId {
        &self.replica_id
    }

    /// Freshly observed committed barrier/application index, when available.
    pub const fn observed_sequence(&self) -> Option<u64> {
        self.observed_sequence
    }

    /// Typed result for this voter.
    pub const fn outcome(&self) -> ReplicaReadinessOutcome {
        self.outcome
    }
}

/// Fresh quorum evidence returned by a replicated session store.
///
/// This is the shared result shape for both the engine/lab probe and the
/// production topology-attested probe. [`Self::scope`] makes that distinction
/// machine-readable. A `Ready` report from
/// [`crate::ConsensusSessionStore::probe_durable_readiness`] proves the
/// Openraft barrier only and MUST NOT authorize production traffic. Production
/// traffic must use
/// [`crate::ConsensusSessionStore::probe_production_durable_readiness`] and
/// require [`Self::is_production_traffic_ready`].
///
/// This report is a point-in-time observation, not a lease and not a promise
/// that a later operation will succeed. Authoritative operations independently
/// repeat the same fail-closed quorum assessment.
#[must_use = "durable readiness evidence must be inspected"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReadinessReport {
    scope: DurableReadinessScope,
    state: DurableReadinessState,
    configured_voters: usize,
    fresh_reachable_voters: usize,
    agreeing_voters: usize,
    required_quorum: usize,
    majority_visible_prefix_index: Option<u64>,
    recovery_progress: DurableRecoveryProgress,
    replica_observations: Vec<ReplicaReadinessObservation>,
}

impl DurableReadinessReport {
    pub(crate) fn new(
        state: DurableReadinessState,
        configured_voters: usize,
        fresh_reachable_voters: usize,
        agreeing_voters: usize,
        required_quorum: usize,
        majority_visible_prefix_index: Option<u64>,
        replica_observations: Vec<ReplicaReadinessObservation>,
    ) -> Self {
        let recovery_state = match state {
            DurableReadinessState::Ready => DurableRecoveryState::Synchronized,
            DurableReadinessState::RecoveryRequired => DurableRecoveryState::RecoveryRequired,
            DurableReadinessState::NoQuorum | DurableReadinessState::TopologyInvalid => {
                DurableRecoveryState::AwaitingQuorum
            }
        };
        Self {
            scope: DurableReadinessScope::EngineOnly,
            state,
            configured_voters,
            fresh_reachable_voters,
            agreeing_voters,
            required_quorum,
            majority_visible_prefix_index,
            recovery_progress: DurableRecoveryProgress::new(recovery_state, None, None, None, None),
            replica_observations,
        }
    }

    pub(crate) const fn with_recovery_progress(
        mut self,
        recovery_progress: DurableRecoveryProgress,
    ) -> Self {
        self.recovery_progress = recovery_progress;
        self
    }

    pub(crate) const fn with_production_topology_attestation(mut self) -> Self {
        self.scope = DurableReadinessScope::ProductionTopologyAttested;
        self
    }

    /// Machine-readable authority scope of this report.
    pub const fn scope(&self) -> DurableReadinessScope {
        self.scope
    }

    /// Overall point-in-time readiness state.
    pub const fn state(&self) -> DurableReadinessState {
        self.state
    }

    /// Whether this report contains fresh evidence from an agreeing majority.
    ///
    /// This does not inspect authority scope and therefore cannot alone
    /// authorize production traffic.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, DurableReadinessState::Ready)
    }

    /// Whether this report can authorize production traffic at this instant.
    ///
    /// The caller must still treat the result as point-in-time evidence and
    /// continuously close traffic when a later production probe fails.
    pub const fn is_production_traffic_ready(&self) -> bool {
        self.is_ready()
            && matches!(
                self.scope,
                DurableReadinessScope::ProductionTopologyAttested
            )
    }

    /// Stable low-cardinality status code suitable for health responses.
    ///
    /// Consumers must pair it with [`Self::scope`]; `"ready"` alone does not
    /// distinguish engine-only from production-attested evidence.
    pub const fn reason_code(&self) -> &'static str {
        self.state.reason_code()
    }

    /// Immutable configured voter count used as the quorum denominator.
    pub const fn configured_voters(&self) -> usize {
        self.configured_voters
    }

    /// Minimum distinct voters proven reachable by the Openraft barrier.
    ///
    /// Openraft does not expose peer identities through this stable report, so
    /// a ready result reports the quorum lower bound rather than guessing a
    /// larger reachability count.
    pub const fn fresh_reachable_voters(&self) -> usize {
        self.fresh_reachable_voters
    }

    /// Minimum distinct voters whose agreement was proven by Openraft commit.
    pub const fn agreeing_voters(&self) -> usize {
        self.agreeing_voters
    }

    /// Number of distinct configured voters required for quorum.
    pub const fn required_quorum(&self) -> usize {
        self.required_quorum
    }

    /// Openraft log index returned by the successful linearizable barrier.
    #[deprecated(
        since = "0.2.0",
        note = "use committed_barrier_index; this compatibility name predates Openraft"
    )]
    pub const fn majority_visible_prefix_index(&self) -> Option<u64> {
        self.majority_visible_prefix_index
    }

    /// Openraft log index returned by the successful linearizable barrier.
    pub const fn committed_barrier_index(&self) -> Option<u64> {
        self.majority_visible_prefix_index
    }

    /// Local Openraft recovery posture and bounded progress counters observed
    /// during this same readiness assessment.
    pub const fn recovery_progress(&self) -> DurableRecoveryProgress {
        self.recovery_progress
    }

    /// Bounded typed observations. The Openraft adapter reports only its local
    /// apply observation and does not expose peer identities.
    pub fn replica_observations(&self) -> &[ReplicaReadinessObservation] {
        &self.replica_observations
    }
}
