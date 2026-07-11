//! Fresh, bounded durable-readiness evidence for replicated session stores.
//!
//! Capability declarations and validated topology are admission evidence. They
//! do not prove that a distinct majority is reachable or agrees on a
//! replication-log prefix now. The types in this module deliberately expose
//! only stable reason codes, counts, and redaction-safe replica identities.

use std::time::Duration;

use crate::topology::ReplicaId;

/// Default end-to-end deadline for one durable-readiness assessment.
pub const DEFAULT_DURABLE_READINESS_TIMEOUT: Duration = Duration::from_secs(2);

/// Default maximum number of replication entries inspected per replica.
///
/// The limit bounds memory and CPU until the replication protocol grows a
/// bounded prefix-proof primitive. Exceeding it fails closed.
pub const DEFAULT_DURABLE_READINESS_MAX_LOG_ENTRIES: usize = 65_536;

/// Hard end-to-end timeout ceiling accepted by [`DurableReadinessOptions`].
pub const MAX_DURABLE_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard per-replica log-entry ceiling accepted by
/// [`DurableReadinessOptions`].
pub const MAX_DURABLE_READINESS_LOG_ENTRIES: usize = 65_536;

/// Work and time limits for one fresh durable-readiness assessment.
///
/// Apply these limits with
/// [`crate::QuorumSessionStore::with_durable_readiness_options`]; that one
/// store-level policy governs both explicit probes and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableReadinessOptions {
    timeout: Duration,
    max_log_entries: usize,
}

impl DurableReadinessOptions {
    /// Construct probe limits.
    ///
    /// A zero timeout or zero entry budget is accepted and fails closed when
    /// the corresponding work cannot complete. Oversized values are capped at
    /// the SDK's fixed work ceilings, so this constructor never panics or
    /// creates unbounded work from operator-provided values.
    pub fn new(timeout: Duration, max_log_entries: usize) -> Self {
        Self {
            timeout: timeout.min(MAX_DURABLE_READINESS_TIMEOUT),
            max_log_entries: max_log_entries.min(MAX_DURABLE_READINESS_LOG_ENTRIES),
        }
    }

    /// End-to-end deadline for the assessment.
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Maximum replication entries that may be loaded from one replica.
    pub const fn max_log_entries(self) -> usize {
        self.max_log_entries
    }
}

impl Default for DurableReadinessOptions {
    fn default() -> Self {
        Self::new(
            DEFAULT_DURABLE_READINESS_TIMEOUT,
            DEFAULT_DURABLE_READINESS_MAX_LOG_ENTRIES,
        )
    }
}

/// Point-in-time result of a fresh durable-readiness assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DurableReadinessState {
    /// A distinct configured majority is reachable and agrees on one prefix.
    Ready,
    /// Fewer than the required distinct voters supplied usable fresh evidence.
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
    /// The replica log conflicts with the majority-visible prefix.
    Divergent,
    /// Safe strict-prefix catch-up failed.
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
    /// A usable fresh log was observed, but this replica was not proven or
    /// caught up to the report's majority-visible prefix.
    Fresh,
    /// The replica already matched the majority-visible prefix.
    Ready,
    /// The replica was safely caught up from a strict shorter prefix.
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

    /// Freshly observed local replication head, when one was obtained.
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

    /// Distinct voters that supplied a fresh replication head.
    pub const fn fresh_reachable_voters(&self) -> usize {
        self.fresh_reachable_voters
    }

    /// Distinct voters that agree with the majority-visible prefix.
    pub const fn agreeing_voters(&self) -> usize {
        self.agreeing_voters
    }

    /// Number of distinct configured voters required for quorum.
    pub const fn required_quorum(&self) -> usize {
        self.required_quorum
    }

    /// Highest contiguous log index supported by a configured majority.
    ///
    /// This is intentionally not called a committed index: the current
    /// coordinator has no durable term/commit proof.
    pub const fn majority_visible_prefix_index(&self) -> Option<u64> {
        self.majority_visible_prefix_index
    }

    /// Per-voter typed observations in configured topology order.
    pub fn replica_observations(&self) -> &[ReplicaReadinessObservation] {
        &self.replica_observations
    }
}
