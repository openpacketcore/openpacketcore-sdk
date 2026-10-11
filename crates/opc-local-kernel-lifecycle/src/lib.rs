//! Shared reset ordering for backends bound to one held local writer domain.
//!
//! Backend crates supply their embedded artifact policy and owned XFRM actor.
//! This crate composes them with owned route reconciliation and consumer-owned
//! companion cleanup. It does not choose session intent or grant activation.
//!
//! [`LocalKernelLifecycle::reset`] requires a stopped scope and explicit
//! authorization to disrupt its declared paths. It first inspects the whole
//! pin layout, then establishes containment, retires XFRM, owned routes and
//! companions, and finally retires every registered BPF graph as one group.
//! Unknown pins and legacy recovery history refuse without erasure. A
//! [`LocalScopeResetReceipt`] permits contained structural rebuild; it cannot
//! authorize a session, an SA or opening containment. Detached external object
//! descriptors remain observable residue and do not prevent local progress.

#![forbid(unsafe_code)]

#[cfg(feature = "store")]
mod authority;
mod layout;
#[cfg(feature = "store")]
mod opening;
#[cfg(feature = "store")]
pub use authority::{
    CommittedScopeEffect, EffectKey, LocalEffectError, LocalEffectUse, ScopeKernelAuthority,
};
mod reset;
mod retry;
pub use retry::{CleanupAttempt, CleanupProgress, CleanupSchedule};
#[cfg(all(test, target_os = "linux", feature = "store"))]
#[path = "../tests/support/quorum.rs"]
mod native_quorum;
mod scope;
#[cfg(feature = "store")]
pub use scope::KernelCompletion;
pub use scope::{
    LocalArtifact, LocalCompanionReset, LocalContainedOperation, LocalGraphActorRegistration,
    LocalGraphBinding, LocalInstalledGraph, LocalKernelLifecycle, LocalOperation,
    LocalRebuildGuard, LocalResetParticipants, LocalScopeEpoch, LocalScopeInspection,
    LocalScopeInspectionResult, LocalScopeResetReceipt, LocalStartupObservation, LocalStartupState,
    LocalXfrmActorRegistration, LocalXfrmReset, NoLocalCompanions,
};

/// Completed or pending phase of a stopped-scope reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetPhase {
    /// Inspect every graph before authorizing any disruption.
    Inspect,
    /// Establish complete containment on every declared path.
    Contain,
    /// Retire the exclusively owned XFRM SPD/SAD.
    Xfrm,
    /// Reconcile only the declared owned route and rule collections.
    Routes,
    /// Await verified cleanup of consumer-owned devices and socket policies.
    Companions,
    /// Detach all owned tc data hooks, then retire object and map pins.
    Artifacts,
    /// Recheck the combined postcondition before releasing the rebuild barrier.
    Verify,
}

/// Payload-free local lifecycle failure. No failure grants rebuild authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLifecycleError {
    /// The declared path, artifact or backend binding is incomplete.
    InvalidPlan,
    /// A required kernel capability is unavailable. This is a terminal admission
    /// refusal for this kernel, not a cleanup failure to retry after restart.
    Unsupported,
    /// A retained native identity or containment predicate failed.
    Scope(opc_linux_gtpu_sys::tc::ScopeError),
    /// A participant could not prove its phase complete.
    Incomplete(ResetPhase),
    /// A reset receipt belongs to another coordinator or an earlier reset.
    Stale,
    /// Opening exceeded its attempt budget and verified containment was restored.
    OpeningAttemptExpired,
    /// The worker or its reply is unavailable; effects may require readback.
    Indeterminate,
}

impl std::fmt::Display for LocalLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local_lifecycle_{self:?}")
    }
}
impl std::error::Error for LocalLifecycleError {}
impl From<opc_linux_gtpu_sys::tc::ScopeError> for LocalLifecycleError {
    fn from(error: opc_linux_gtpu_sys::tc::ScopeError) -> Self {
        match error {
            opc_linux_gtpu_sys::tc::ScopeError::Unsupported => Self::Unsupported,
            other => Self::Scope(other),
        }
    }
}
