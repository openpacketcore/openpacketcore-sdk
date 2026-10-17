//! Results of bounded, planned retirement of a durable consensus voter.

use std::time::Duration;

use crate::{ConsensusNodeId, DURABLE_CONSENSUS_TIMING_PROFILE};

/// The handoff result retained by one clone-wide store shutdown.
///
/// A successful store shutdown also joins its engine and storage owners. This
/// result describes the preceding handoff; a fallback does not certify a
/// successor or a surviving quorum. Accepted writes retain their original
/// completion or same-request-ID recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlannedShutdownOutcome {
    /// A fresh successor vote and quorum read proof cover the accepted prefix.
    LeaderTransferred {
        /// Current voter selected by the retiring leader.
        successor: ConsensusNodeId,
    },
    /// The engine atomically retired a follower or candidate from campaigning.
    FollowerRetired,
    /// The bounded handoff failed; ordinary engine shutdown still proceeded.
    Fallback {
        /// Stable, payload-free explanation of the failed handoff.
        reason: PlannedShutdownFallback,
    },
}

/// Why a planned handoff could not establish successor authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlannedShutdownFallback {
    /// Local durable authority was not admitted for a handoff.
    #[error("local voter is not admitted")]
    NotAdmitted,
    /// The current membership has no other eligible voter.
    #[error("no eligible successor voter")]
    NoEligibleVoter,
    /// Removing this voter cannot leave a majority of the current membership.
    #[error("insufficient surviving voters")]
    InsufficientSurvivingVoters,
    /// The membership or durable authority changed during preparation.
    #[error("consensus scope changed")]
    ScopeChanged,
    /// The consensus engine could not prepare this incarnation for retirement.
    #[error("consensus engine could not prepare shutdown")]
    EngineUnavailable,
    /// Too few surviving voters acknowledged release of the retiring vote lease.
    #[error("surviving vote leases could not be released")]
    SurvivingQuorumUnavailable,
    /// No selected voter applied the accepted prefix before the original deadline.
    #[error("no up-to-date successor before the handoff deadline")]
    NoUpToDateVoter,
    /// The selected voter rejected the authenticated engine-issued handoff.
    #[error("successor rejected leadership transfer")]
    SuccessorRejected,
    /// A fresh successor vote and quorum read proof were not obtained in time.
    #[error("successor authority could not be confirmed")]
    SuccessorUnconfirmed,
    /// Preparation could not finish within its original deadline.
    #[error("planned shutdown preparation deadline elapsed")]
    DeadlineElapsed,
}

/// Reserve part of the existing operation budget for the engine/storage drain.
///
/// Automatic preparation gets at most one vote-RPC ceiling and half of the
/// configured complete-operation budget. This does not extend client deadlines
/// or alter ordinary elections. Explicit two-phase preparation may use its own
/// existing complete-operation deadline before the separate shutdown call.
#[must_use]
pub fn planned_shutdown_timeout(operation_timeout: Duration) -> Duration {
    (operation_timeout / 2).min(Duration::from_millis(
        DURABLE_CONSENSUS_TIMING_PROFILE.vote_timeout_millis,
    ))
}
