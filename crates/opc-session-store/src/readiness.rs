//! Fresh, bounded durable-readiness evidence for replicated session stores.
//!
//! Capability declarations and validated topology are admission evidence. They
//! do not prove that Openraft can complete a linearizable barrier now. The
//! types in this module deliberately expose only stable reason codes, counts,
//! committed-barrier indexes, and redaction-safe replica identities.

use crate::topology::ReplicaId;

/// Point-in-time result of a fresh durable-readiness assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DurableReadinessState {
    /// Openraft completed a linearizable barrier and local apply wait against
    /// the admitted voting configuration.
    Ready,
    /// Openraft could not complete the barrier before the operation deadline.
    NoQuorum,
    /// The coordinator was not built from an admitted topology.
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
/// This report is a point-in-time observation, not a lease and not a promise
/// that a later operation will succeed. Authoritative operations independently
/// repeat the same fail-closed quorum assessment.
#[must_use = "durable readiness evidence must be checked before opening traffic"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReadinessReport {
    state: DurableReadinessState,
    configured_voters: usize,
    fresh_reachable_voters: usize,
    agreeing_voters: usize,
    required_quorum: usize,
    majority_visible_prefix_index: Option<u64>,
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
        Self {
            state,
            configured_voters,
            fresh_reachable_voters,
            agreeing_voters,
            required_quorum,
            majority_visible_prefix_index,
            replica_observations,
        }
    }

    /// Overall point-in-time readiness state.
    pub const fn state(&self) -> DurableReadinessState {
        self.state
    }

    /// Whether this report contains fresh evidence from an agreeing majority.
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, DurableReadinessState::Ready)
    }

    /// Stable low-cardinality status code suitable for health responses.
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

    /// Bounded typed observations. The Openraft adapter reports only its local
    /// apply observation and does not expose peer identities.
    pub fn replica_observations(&self) -> &[ReplicaReadinessObservation] {
        &self.replica_observations
    }
}
