//! Cancellation-safe staged composite XFRM install with a caller-visible
//! mutation journal.
//!
//! [`install_sa_policy_with_rollback`](crate::install_sa_policy_with_rollback)
//! mutates backend state across multiple async awaits. Dropping that future
//! after an acknowledged backend mutation but before it returns yields no
//! typed outcome and runs no retained cleanup authority, so a consumer cannot
//! safely infer what the composite owned at the cancellation point.
//!
//! [`XfrmStagedInstall`] closes that gap without changing the existing helper:
//! the caller clones an [`XfrmInstallJournal`] before polling
//! [`XfrmStagedInstall::run`], and the journal records every acknowledged
//! backend mutation at the moment it is acknowledged, outside the future. If
//! the future is dropped at any point, [`XfrmInstallJournal::ownership`]
//! reports exactly what the operation may own and
//! [`XfrmInstallJournal::recovery_plan`] hands the caller the exact,
//! never-broadened removal intents for that residue. The journal never
//! authorizes deletion of a pre-existing SA or policy: an `AlreadyExists`
//! failure is definitive backend evidence that the matching mutation was not
//! acquired by this operation, so it never enters the recovery plan.

use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    RemovePolicyRequest, RemoveSaRequest, XfrmBackend, XfrmCompositeInstallError,
    XfrmCompositeInstallRequest, XfrmCompositeOperation, XfrmCompositeOutcome, XfrmError,
};

/// Typed mutation ownership of a staged composite install.
///
/// Every variant is redaction-safe: it carries only stable stage labels and
/// never SA/policy identities, SPIs, addresses, or key material. The exact
/// removal identities for residue are exposed separately through
/// [`XfrmInstallRecoveryPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmInstallOwnership {
    /// No backend mutation was acquired by this operation. There is no
    /// cleanup obligation; a recovery plan in this state is empty. This is
    /// also the state after a definitive SA install failure, including
    /// `AlreadyExists`: the pre-existing SA is not owned by this operation
    /// and must not be removed on its behalf.
    NotStarted,
    /// The SA install was issued but its outcome was not observed, for
    /// example because the `run` future was dropped while the SA await was
    /// in flight. The SA mutation may or may not be applied; exact SA
    /// removal authority (idempotent on `NotFound`) is retained. This state
    /// never reads as [`Self::NotStarted`]: an issued-but-unobserved install
    /// is a cleanup obligation, not proof that nothing was acquired.
    SaInFlight,
    /// The SA install was acknowledged and no policy residue is owned: either
    /// policy install has not been issued yet, or it was definitively
    /// rejected (including `AlreadyExists`) and the helper's SA rollback
    /// failed or has not completed. Exact SA removal authority is retained.
    SaAcquired,
    /// The SA install was acknowledged and the policy install was issued but
    /// its outcome was not observed, for example because the `run` future was
    /// dropped while the policy await was in flight. The policy mutation may
    /// or may not be applied; exact removal authority for both the policy
    /// (idempotent on `NotFound`) and the SA is retained.
    PolicyInFlight,
    /// The complete install (SA plus policy) was acknowledged. Exact removal
    /// authority for both, in policy-first order, is retained.
    Complete,
    /// The helper fully rolled its own mutation back after a definitive
    /// failure. No residual ownership remains and the recovery plan is empty.
    RolledBack,
    /// Recovery completed: every retained removal intent was applied or
    /// proven absent (`NotFound`). The journal no longer authorizes removal.
    Recovered,
    /// The backend reported [`XfrmError::StateIndeterminate`]: a mutation may
    /// have been accepted but its final state could not be proven. The exact
    /// residue candidates remain recoverable through the recovery plan, and
    /// [`XfrmInstallRecoveryPlan::requires_readback`] recommends a classified
    /// readback before or alongside destructive recovery.
    Indeterminate {
        /// Operation whose final state is indeterminate.
        operation: XfrmCompositeOperation,
    },
}

impl XfrmInstallOwnership {
    /// Stable machine-readable ownership label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::SaInFlight => "sa_in_flight",
            Self::SaAcquired => "sa_acquired",
            Self::PolicyInFlight => "policy_in_flight",
            Self::Complete => "complete",
            Self::RolledBack => "rolled_back",
            Self::Recovered => "recovered",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }

    /// True when this operation may still own backend residue that a
    /// recovery plan would remove.
    pub const fn has_residue(self) -> bool {
        matches!(
            self,
            Self::SaInFlight
                | Self::SaAcquired
                | Self::PolicyInFlight
                | Self::Complete
                | Self::Indeterminate { .. }
        )
    }
}

/// Exact removal intents retained for staged-install residue.
///
/// Intents are built once from the original
/// [`XfrmCompositeInstallRequest`] identity and are never broadened: a plan
/// removes at most the exact SA (`destination`, `protocol`, `spi`, `mark`)
/// and the exact policy (`selector`, `direction`, `mark`) that this operation
/// may have acquired. It never contains an intent for state the backend
/// rejected with `AlreadyExists`, because that state is not owned by this
/// operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmInstallRecoveryPlan {
    policy: Option<RemovePolicyRequest>,
    sa: Option<RemoveSaRequest>,
    requires_readback: bool,
}

impl XfrmInstallRecoveryPlan {
    /// Empty plan: no cleanup obligation.
    const fn empty() -> Self {
        Self {
            policy: None,
            sa: None,
            requires_readback: false,
        }
    }

    /// True when no removal intent is retained.
    pub const fn is_empty(&self) -> bool {
        self.policy.is_none() && self.sa.is_none()
    }

    /// Exact policy removal intent, when policy residue may be owned.
    pub const fn policy(&self) -> Option<&RemovePolicyRequest> {
        self.policy.as_ref()
    }

    /// Exact SA removal intent, when SA residue may be owned.
    pub const fn sa(&self) -> Option<&RemoveSaRequest> {
        self.sa.as_ref()
    }

    /// True when the backend reported an indeterminate state and a classified
    /// readback is recommended before or alongside destructive recovery.
    pub const fn requires_readback(&self) -> bool {
        self.requires_readback
    }
}

/// Error returned by [`XfrmInstallJournal::recover`].
///
/// Variants deliberately carry only the redaction-safe backend error; removal
/// identities stay in the caller-held [`XfrmInstallRecoveryPlan`].
#[derive(Debug, Clone)]
pub enum XfrmInstallRecoveryError {
    /// Policy removal during recovery failed with a non-`NotFound` error.
    RemovePolicyFailed {
        /// Backend error from policy removal.
        source: XfrmError,
    },
    /// SA removal during recovery failed with a non-`NotFound` error.
    RemoveSaFailed {
        /// Backend error from SA removal.
        source: XfrmError,
    },
    /// Recovery was requested while the staged install runner had not
    /// finished: its `run` future is still live, or it was never polled.
    /// Recovery is rejected because the runner may still acquire further
    /// mutations that a completed recovery would permanently mask. Retry
    /// after the `run` future completed or was dropped.
    RunnerNotFinished,
}

impl XfrmInstallRecoveryError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RemovePolicyFailed { .. } => "xfrm_install_recovery_remove_policy_failed",
            Self::RemoveSaFailed { .. } => "xfrm_install_recovery_remove_sa_failed",
            Self::RunnerNotFinished => "xfrm_install_recovery_runner_not_finished",
        }
    }
}

impl fmt::Display for XfrmInstallRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmInstallRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RemovePolicyFailed { source } | Self::RemoveSaFailed { source } => Some(source),
            Self::RunnerNotFinished => None,
        }
    }
}

/// Internal staged-install progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    NotStarted,
    SaInFlight,
    SaAcquired,
    PolicyInFlight,
    Complete,
}

/// Lifecycle of the staged install runner, tracked so recovery can refuse to
/// race a runner that may still acquire further mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunLifecycle {
    /// The `run` future was never polled.
    NotStarted,
    /// The `run` future was polled and has neither completed nor been
    /// dropped.
    Running,
    /// The `run` future completed or was dropped.
    Finished,
}

/// Guard owned by the `run` future. Creating it marks the runner live;
/// dropping the future — by completion or by cancellation — drops the guard
/// and marks the runner finished, so a drop-cancelled install stays
/// recoverable while a live one rejects recovery.
#[derive(Debug)]
struct RunGuard<'a> {
    journal: &'a XfrmInstallJournal,
}

impl RunGuard<'_> {
    fn begin(&self) {
        self.journal.state().lifecycle = RunLifecycle::Running;
    }
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.journal.state().lifecycle = RunLifecycle::Finished;
    }
}

#[derive(Debug)]
struct JournalState {
    stage: Stage,
    lifecycle: RunLifecycle,
    sa_cleared: bool,
    policy_cleared: bool,
    rolled_back: bool,
    recovered: bool,
    indeterminate: Option<XfrmCompositeOperation>,
}

impl JournalState {
    const fn new() -> Self {
        Self {
            stage: Stage::NotStarted,
            lifecycle: RunLifecycle::NotStarted,
            sa_cleared: false,
            policy_cleared: false,
            rolled_back: false,
            recovered: false,
            indeterminate: None,
        }
    }

    fn ownership(&self) -> XfrmInstallOwnership {
        if self.recovered {
            return XfrmInstallOwnership::Recovered;
        }
        if let Some(operation) = self.indeterminate {
            return XfrmInstallOwnership::Indeterminate { operation };
        }
        match self.stage {
            Stage::Complete => XfrmInstallOwnership::Complete,
            // A completed helper rollback retires all owned residue.
            _ if self.rolled_back => XfrmInstallOwnership::RolledBack,
            Stage::SaInFlight => XfrmInstallOwnership::SaInFlight,
            Stage::SaAcquired => XfrmInstallOwnership::SaAcquired,
            Stage::PolicyInFlight => XfrmInstallOwnership::PolicyInFlight,
            Stage::NotStarted => XfrmInstallOwnership::NotStarted,
        }
    }

    fn plan(&self, inner: &JournalInner) -> XfrmInstallRecoveryPlan {
        if self.recovered {
            return XfrmInstallRecoveryPlan::empty();
        }
        // The SA may be owned once its install was issued without an observed
        // definitive rejection, acknowledged, or reported indeterminate, until
        // the helper rollback or a recovery cleared it. Covering the
        // in-flight stage costs one harmless `NotFound`-idempotent removal
        // when the SA was never acquired, and covers residue when the backend
        // applied the SA but the acknowledgement was never observed.
        let sa_acquired =
            matches!(
                self.stage,
                Stage::SaInFlight | Stage::SaAcquired | Stage::PolicyInFlight | Stage::Complete
            ) || matches!(self.indeterminate, Some(XfrmCompositeOperation::InstallSa));
        let sa = if sa_acquired && !self.sa_cleared {
            Some(inner.remove_sa)
        } else {
            None
        };
        // The policy may be owned only once its install was issued without a
        // definitive rejection observed, or reported indeterminate. A
        // definitive failure (including `AlreadyExists`) resets the stage to
        // `SaAcquired` before the rollback await, so a pre-existing policy
        // never enters the plan.
        let policy_possible = matches!(self.stage, Stage::PolicyInFlight | Stage::Complete)
            || matches!(
                self.indeterminate,
                Some(XfrmCompositeOperation::InstallPolicy)
            );
        let policy = if policy_possible && !self.policy_cleared {
            Some(inner.remove_policy.clone())
        } else {
            None
        };
        XfrmInstallRecoveryPlan {
            policy,
            sa,
            requires_readback: self.indeterminate.is_some(),
        }
    }
}

#[derive(Debug)]
struct JournalInner {
    remove_sa: RemoveSaRequest,
    remove_policy: RemovePolicyRequest,
    state: Mutex<JournalState>,
}

/// Caller-visible mutation journal for a staged composite install.
///
/// Clone the journal from [`XfrmStagedInstall::journal`] before polling
/// [`XfrmStagedInstall::run`]. The handle is cheap to clone, `Send + Sync`,
/// and shares one authoritative state with the running operation, so it keeps
/// reporting exact mutation ownership even after the `run` future is dropped
/// at any await point.
///
/// The journal is the only cleanup authority the operation retains: while
/// [`Self::ownership`] reports residue, the matching
/// [`Self::recovery_plan`] holds the exact removal intents; once recovery
/// completes the journal transitions to [`XfrmInstallOwnership::Recovered`]
/// and stops authorizing removal.
#[derive(Debug, Clone)]
pub struct XfrmInstallJournal {
    inner: Arc<JournalInner>,
}

impl XfrmInstallJournal {
    fn new(remove_sa: RemoveSaRequest, remove_policy: RemovePolicyRequest) -> Self {
        Self {
            inner: Arc::new(JournalInner {
                remove_sa,
                remove_policy,
                state: Mutex::new(JournalState::new()),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, JournalState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Current typed mutation ownership. Safe to call at any time, including
    /// while the `run` future is paused at an await or after it was dropped.
    pub fn ownership(&self) -> XfrmInstallOwnership {
        self.state().ownership()
    }

    /// Exact removal intents for the residue this operation may currently
    /// own. The plan is empty when there is no cleanup obligation and never
    /// contains identities the backend definitively rejected.
    pub fn recovery_plan(&self) -> XfrmInstallRecoveryPlan {
        self.state().plan(&self.inner)
    }

    /// Apply the current recovery plan against the backend.
    ///
    /// Removal order is policy first, then SA, matching
    /// [`crate::XFRM_COMPOSITE_REMOVE_ORDER`]. Removal uses exactly the
    /// identities retained in [`Self::recovery_plan`]; it is never broadened.
    /// `NotFound` is treated as idempotent success for each intent, so
    /// retrying recovery after a partial failure or after residue was removed
    /// externally is safe. When every intent is applied or proven absent the
    /// journal transitions to [`XfrmInstallOwnership::Recovered`]; a later
    /// call is then a no-op.
    ///
    /// When the plan [`XfrmInstallRecoveryPlan::requires_readback`], callers
    /// should reconcile backend state with a classified readback (for example
    /// [`XfrmBackend::query_sa`]) before relying on the result; recovery still
    /// uses only the exact retained identities.
    ///
    /// # Lifecycle
    ///
    /// Recovery must not race the install runner: a completed recovery
    /// permanently retires the journal's removal authority, so applying it
    /// while the runner may still acquire further mutations would orphan
    /// them. This call therefore fails with
    /// [`XfrmInstallRecoveryError::RunnerNotFinished`] while the `run` future
    /// is still live, and also before it was ever polled (the runner may
    /// still be started afterwards). Call it only after the `run` future
    /// completed or was dropped; a drop-cancelled runner counts as finished
    /// and stays recoverable.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmInstallRecoveryError`] on the first non-`NotFound`
    /// backend failure. Intents already cleared stay cleared, so a retry
    /// resumes with the remaining residue only.
    pub async fn recover<B>(&self, backend: &B) -> Result<(), XfrmInstallRecoveryError>
    where
        B: XfrmBackend + ?Sized,
    {
        if self.state().lifecycle != RunLifecycle::Finished {
            return Err(XfrmInstallRecoveryError::RunnerNotFinished);
        }
        let plan = self.recovery_plan();

        if let Some(policy) = plan.policy() {
            match backend.remove_policy(policy.clone()).await {
                Ok(()) | Err(XfrmError::NotFound) => {
                    self.state().policy_cleared = true;
                }
                Err(source) => {
                    return Err(XfrmInstallRecoveryError::RemovePolicyFailed { source });
                }
            }
        }

        if let Some(sa) = plan.sa() {
            match backend.remove_sa(*sa).await {
                Ok(()) | Err(XfrmError::NotFound) => {
                    self.state().sa_cleared = true;
                }
                Err(source) => {
                    return Err(XfrmInstallRecoveryError::RemoveSaFailed { source });
                }
            }
        }

        self.state().recovered = true;
        Ok(())
    }
}

/// Cancellation-safe staged SA-plus-policy composite install.
///
/// This is the journal-backed counterpart of
/// [`install_sa_policy_with_rollback`](crate::install_sa_policy_with_rollback):
/// [`Self::run`] performs the same backend calls in the same order
/// ([`crate::XFRM_COMPOSITE_INSTALL_ORDER`], with
/// [`crate::XFRM_COMPOSITE_INSTALL_ROLLBACK_ORDER`] after a policy failure)
/// and returns the same [`XfrmCompositeOutcome`] /
/// [`XfrmCompositeInstallError`] evidence. The difference is that every
/// acknowledged mutation is recorded in the caller-held [`XfrmInstallJournal`]
/// at the moment it is acknowledged, so dropping the `run` future at any
/// await point leaves exact, typed ownership behind instead of an opaque
/// cancellation.
///
/// Drive one `run` future per staged install. Cloning the journal is cheap
/// and intended; polling several `run` futures of the same staged install
/// concurrently is not. Call [`XfrmInstallJournal::recover`] only after the
/// `run` future completed or was dropped: recovery while the runner is live
/// (or before it ever ran) is rejected with
/// [`XfrmInstallRecoveryError::RunnerNotFinished`] so a completed recovery
/// cannot orphan mutations the runner may still acquire.
#[derive(Debug)]
pub struct XfrmStagedInstall {
    request: XfrmCompositeInstallRequest,
    journal: XfrmInstallJournal,
}

impl XfrmStagedInstall {
    /// Stage a composite install. No backend call is made until [`Self::run`]
    /// is polled.
    #[must_use]
    pub fn new(request: XfrmCompositeInstallRequest) -> Self {
        let journal = XfrmInstallJournal::new(
            request.rollback_remove_sa(),
            request.rollback_remove_policy(),
        );
        Self { request, journal }
    }

    /// Clone the caller-visible mutation journal for this staged install.
    pub fn journal(&self) -> XfrmInstallJournal {
        self.journal.clone()
    }

    /// Run the staged install, journaling every acknowledged mutation.
    ///
    /// # Cancel safety
    ///
    /// Dropping the returned future is safe at every await point: the journal
    /// obtained from [`Self::journal`] keeps the exact
    /// [`XfrmInstallOwnership`] and recovery authority for any mutation that
    /// was acknowledged (or, for an in-flight SA or policy install, possibly
    /// applied) before the drop.
    ///
    /// # Errors
    ///
    /// Returns the same [`XfrmCompositeInstallError`] evidence as
    /// [`install_sa_policy_with_rollback`](crate::install_sa_policy_with_rollback):
    /// SA failure before any mutation, policy failure with successful
    /// rollback, or policy failure with rollback failure. A backend
    /// [`XfrmError::StateIndeterminate`] is additionally recorded in the
    /// journal as [`XfrmInstallOwnership::Indeterminate`] so it stays
    /// explicitly recoverable instead of collapsing into a generic error.
    pub async fn run<B>(
        &self,
        backend: &B,
    ) -> Result<XfrmCompositeOutcome, XfrmCompositeInstallError>
    where
        B: XfrmBackend + ?Sized,
    {
        // The guard lives inside this future: it is created on the first poll
        // and dropped when the future completes or is dropped, so the journal
        // can tell a finished (recoverable) runner from a live one.
        let guard = RunGuard {
            journal: &self.journal,
        };
        guard.begin();

        // Record the in-flight SA install synchronously before the await: if
        // the future is dropped while the install is in flight, the journal
        // must retain exact SA recovery authority instead of reporting
        // `NotStarted` while the backend may have applied the SA.
        self.journal.state().stage = Stage::SaInFlight;
        if let Err(source) = backend.install_sa(self.request.sa.clone()).await {
            let indeterminate = matches!(&source, XfrmError::StateIndeterminate { .. });
            if indeterminate {
                // The SA mutation may have been accepted; retain exact
                // recovery authority for it as possible residue.
                self.journal.state().indeterminate = Some(XfrmCompositeOperation::InstallSa);
            } else {
                // Definitive rejection (including `AlreadyExists`): this
                // operation did not acquire the SA and must never remove the
                // pre-existing one.
                self.journal.state().stage = Stage::NotStarted;
            }
            let outcome = if indeterminate {
                XfrmCompositeOutcome::indeterminate(XfrmCompositeOperation::InstallSa)
            } else {
                XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa)
            };
            return Err(XfrmCompositeInstallError::InstallSaFailed { source, outcome });
        }
        self.journal.state().stage = Stage::SaAcquired;

        self.journal.state().stage = Stage::PolicyInFlight;
        if let Err(source) = backend.install_policy(self.request.policy.clone()).await {
            let indeterminate = matches!(&source, XfrmError::StateIndeterminate { .. });
            {
                let mut state = self.journal.state();
                if indeterminate {
                    // The policy mutation may have been accepted; retain it
                    // as possible residue alongside the SA.
                    state.indeterminate = Some(XfrmCompositeOperation::InstallPolicy);
                } else {
                    // Definitive rejection (including `AlreadyExists`): this
                    // operation did not acquire the policy and must never
                    // remove the pre-existing one.
                    state.stage = Stage::SaAcquired;
                }
            }
            let rollback_request = self.request.rollback_remove_sa();
            return match backend.remove_sa(rollback_request).await {
                Ok(()) => {
                    let mut state = self.journal.state();
                    state.sa_cleared = true;
                    state.rolled_back = true;
                    Err(XfrmCompositeInstallError::PolicyInstallRolledBack {
                        source,
                        outcome: XfrmCompositeOutcome::rolled_back(
                            XfrmCompositeOperation::InstallPolicy,
                        ),
                    })
                }
                Err(rollback) => Err(XfrmCompositeInstallError::PolicyInstallRollbackFailed {
                    source,
                    rollback,
                    outcome: XfrmCompositeOutcome::rollback_failed(
                        XfrmCompositeOperation::InstallPolicy,
                    ),
                }),
            };
        }
        self.journal.state().stage = Stage::Complete;

        Ok(XfrmCompositeOutcome::applied())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard};

    use async_trait::async_trait;
    use tokio::sync::{oneshot, Notify};

    use super::*;
    use crate::{
        AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, IpAddress, PolicyParameters,
        QuerySaRequest, RekeyPolicyRequest, RekeySaRequest, SaParameters, SaState, SpiAllocation,
        XfrmAction, XfrmDirection, XfrmId, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
    };

    /// Where a gate blocks the `install_sa`/`install_policy` mutation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GateMode {
        /// Block before the mutation is applied.
        BeforeApply,
        /// Apply the mutation, signal, then block before returning.
        AfterApply,
    }

    /// Stateful fake backend with oneshot gates so tests can drop the staged
    /// install future at exact cancellation points.
    #[derive(Debug)]
    struct GatedBackend {
        operations: Mutex<Vec<&'static str>>,
        sas: Mutex<Vec<RemoveSaRequest>>,
        policies: Mutex<Vec<RemovePolicyRequest>>,
        removed_sa_requests: Mutex<Vec<RemoveSaRequest>>,
        removed_policy_requests: Mutex<Vec<RemovePolicyRequest>>,
        install_sa_error: Option<XfrmError>,
        install_policy_error: Option<XfrmError>,
        remove_sa_error: Mutex<Option<XfrmError>>,
        sa_gate: Mutex<Option<oneshot::Receiver<()>>>,
        policy_gate: Mutex<Option<oneshot::Receiver<()>>>,
        sa_gate_mode: Option<GateMode>,
        policy_gate_mode: Option<GateMode>,
        sa_started: Notify,
        sa_applied: Notify,
        policy_started: Notify,
        policy_applied: Notify,
    }

    impl GatedBackend {
        fn new() -> Self {
            Self {
                operations: Mutex::new(Vec::new()),
                sas: Mutex::new(Vec::new()),
                policies: Mutex::new(Vec::new()),
                removed_sa_requests: Mutex::new(Vec::new()),
                removed_policy_requests: Mutex::new(Vec::new()),
                install_sa_error: None,
                install_policy_error: None,
                remove_sa_error: Mutex::new(None),
                sa_gate: Mutex::new(None),
                policy_gate: Mutex::new(None),
                sa_gate_mode: None,
                policy_gate_mode: None,
                sa_started: Notify::new(),
                sa_applied: Notify::new(),
                policy_started: Notify::new(),
                policy_applied: Notify::new(),
            }
        }

        fn lock<'a, T>(mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
            mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn record(&self, operation: &'static str) {
            Self::lock(&self.operations).push(operation);
        }

        fn operations(&self) -> Vec<&'static str> {
            Self::lock(&self.operations).clone()
        }

        fn sas(&self) -> Vec<RemoveSaRequest> {
            Self::lock(&self.sas).clone()
        }

        fn policies(&self) -> Vec<RemovePolicyRequest> {
            Self::lock(&self.policies).clone()
        }

        fn removed_sa_requests(&self) -> Vec<RemoveSaRequest> {
            Self::lock(&self.removed_sa_requests).clone()
        }

        fn removed_policy_requests(&self) -> Vec<RemovePolicyRequest> {
            Self::lock(&self.removed_policy_requests).clone()
        }

        fn preinstall_sa(&self, identity: RemoveSaRequest) {
            Self::lock(&self.sas).push(identity);
        }

        fn preinstall_policy(&self, identity: RemovePolicyRequest) {
            Self::lock(&self.policies).push(identity);
        }

        fn gate_sa(&self) -> oneshot::Sender<()> {
            let (sender, receiver) = oneshot::channel();
            *Self::lock(&self.sa_gate) = Some(receiver);
            sender
        }

        fn gate_policy(&self) -> oneshot::Sender<()> {
            let (sender, receiver) = oneshot::channel();
            *Self::lock(&self.policy_gate) = Some(receiver);
            sender
        }

        fn fail_remove_sa(&self, error: XfrmError) {
            *Self::lock(&self.remove_sa_error) = Some(error);
        }

        fn clear_remove_sa_error(&self) {
            *Self::lock(&self.remove_sa_error) = None;
        }

        fn take_sa_gate(&self) -> Option<oneshot::Receiver<()>> {
            Self::lock(&self.sa_gate).take()
        }

        fn take_policy_gate(&self) -> Option<oneshot::Receiver<()>> {
            Self::lock(&self.policy_gate).take()
        }
    }

    #[async_trait]
    impl XfrmBackend for GatedBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test allocate_spi",
            })
        }

        async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
            self.record("install_sa");
            self.sa_started.notify_one();
            let identity = RemoveSaRequest {
                destination: request.parameters.id.destination,
                protocol: request.parameters.id.protocol,
                spi: request.parameters.id.spi,
                mark: request.parameters.mark,
            };
            match self.sa_gate_mode {
                Some(GateMode::BeforeApply) => {
                    if let Some(gate) = self.take_sa_gate() {
                        let _ = gate.await;
                    }
                }
                Some(GateMode::AfterApply) => {
                    // Apply the mutation, signal, then block the
                    // acknowledgement: a cancellation here models an applied
                    // SA whose `Ok` was never observed.
                    if Self::lock(&self.sas).contains(&identity) {
                        return Err(XfrmError::AlreadyExists);
                    }
                    Self::lock(&self.sas).push(identity);
                    self.sa_applied.notify_one();
                    if let Some(gate) = self.take_sa_gate() {
                        let _ = gate.await;
                    }
                    return Ok(());
                }
                None => {}
            }
            if Self::lock(&self.sas).contains(&identity) {
                return Err(XfrmError::AlreadyExists);
            }
            if let Some(error) = self.install_sa_error.clone() {
                return Err(error);
            }
            Self::lock(&self.sas).push(identity);
            Ok(())
        }

        async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test query_sa",
            })
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test rekey_sa",
            })
        }

        async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
            self.record("remove_sa");
            Self::lock(&self.removed_sa_requests).push(request);
            if let Some(error) = Self::lock(&self.remove_sa_error).clone() {
                return Err(error);
            }
            let mut sas = Self::lock(&self.sas);
            if let Some(position) = sas.iter().position(|sa| *sa == request) {
                sas.remove(position);
                Ok(())
            } else {
                Err(XfrmError::NotFound)
            }
        }

        async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
            self.record("install_policy");
            self.policy_started.notify_one();
            let identity = RemovePolicyRequest {
                selector: request.parameters.selector.clone(),
                direction: request.parameters.direction,
                mark: request.parameters.mark,
            };
            match self.policy_gate_mode {
                Some(GateMode::BeforeApply) => {
                    if let Some(gate) = self.take_policy_gate() {
                        let _ = gate.await;
                    }
                }
                Some(GateMode::AfterApply) => {
                    if Self::lock(&self.policies).contains(&identity) {
                        return Err(XfrmError::AlreadyExists);
                    }
                    Self::lock(&self.policies).push(identity);
                    self.policy_applied.notify_one();
                    if let Some(gate) = self.take_policy_gate() {
                        let _ = gate.await;
                    }
                    return Ok(());
                }
                None => {}
            }
            if Self::lock(&self.policies).contains(&identity) {
                return Err(XfrmError::AlreadyExists);
            }
            if let Some(error) = self.install_policy_error.clone() {
                return Err(error);
            }
            Self::lock(&self.policies).push(identity);
            Ok(())
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test rekey_policy",
            })
        }

        async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
            self.record("remove_policy");
            Self::lock(&self.removed_policy_requests).push(request.clone());
            let mut policies = Self::lock(&self.policies);
            if let Some(position) = policies.iter().position(|policy| *policy == request) {
                policies.remove(position);
                Ok(())
            } else {
                Err(XfrmError::NotFound)
            }
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::mock())
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50)
    }

    fn sa_parameters() -> SaParameters {
        SaParameters {
            selector: selector(),
            id: XfrmId {
                destination: ipv4(10, 0, 0, 2),
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: ipv4(10, 0, 0, 1),
            request_id: None,
            auth: None,
            crypt: None,
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: Default::default(),
            replay_window: 32,
            replay_state: None,
            encap: None,
            mark: None,
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        }
    }

    fn policy_parameters() -> PolicyParameters {
        PolicyParameters {
            selector: selector(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: sa_parameters().id,
                source_address: ipv4(10, 0, 0, 1),
                request_id: None,
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: None,
        }
    }

    fn install_request() -> XfrmCompositeInstallRequest {
        XfrmCompositeInstallRequest {
            sa: InstallSaRequest {
                parameters: sa_parameters(),
            },
            policy: InstallPolicyRequest {
                parameters: policy_parameters(),
            },
        }
    }

    fn expected_remove_sa() -> RemoveSaRequest {
        install_request().rollback_remove_sa()
    }

    fn expected_remove_policy() -> RemovePolicyRequest {
        install_request().rollback_remove_policy()
    }

    #[tokio::test]
    async fn cancellation_before_first_mutation_leaves_no_cleanup_obligation() {
        let backend = GatedBackend::new();

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        // Drop the `run` future before it is ever polled: no backend call is
        // issued, so no mutation can have been acquired.
        drop(staged.run(&backend));

        assert!(backend.operations().is_empty());
        assert_eq!(journal.ownership(), XfrmInstallOwnership::NotStarted);
        assert!(!journal.ownership().has_residue());
        assert!(journal.recovery_plan().is_empty());

        // The runner may still be started later, so recovery is rejected
        // instead of permanently retiring the journal's removal authority.
        let error = journal
            .recover(&backend)
            .await
            .expect_err("recovery before the runner finished is rejected");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        assert_eq!(error.as_str(), "xfrm_install_recovery_runner_not_finished");
        assert!(backend.removed_sa_requests().is_empty());
        assert!(backend.removed_policy_requests().is_empty());
    }

    #[tokio::test]
    async fn cancellation_during_sa_install_before_apply_keeps_idempotent_sa_recovery() {
        let backend = GatedBackend {
            sa_gate_mode: Some(GateMode::BeforeApply),
            ..GatedBackend::new()
        };
        let gate = backend.gate_sa();
        let backend = Arc::new(backend);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = backend.clone();
        let handle = tokio::spawn(async move { staged.run(runner.as_ref()).await });
        backend.sa_started.notified().await;
        handle.abort();
        assert!(handle.await.is_err());
        drop(gate);

        // The install was issued but never observed: the journal must not
        // report `NotStarted` while the SA await was in flight.
        assert_eq!(journal.ownership(), XfrmInstallOwnership::SaInFlight);
        assert!(journal.ownership().has_residue());
        let plan = journal.recovery_plan();
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), None);

        // The SA was never applied: `NotFound` is idempotent success.
        journal
            .recover(backend.as_ref())
            .await
            .expect("recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(backend.operations(), vec!["install_sa", "remove_sa"]);
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
        assert!(backend.sas().is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_sa_applied_before_ack_retains_exact_sa_recovery() {
        let backend = GatedBackend {
            sa_gate_mode: Some(GateMode::AfterApply),
            ..GatedBackend::new()
        };
        let gate = backend.gate_sa();
        let backend = Arc::new(backend);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = backend.clone();
        let handle = tokio::spawn(async move { staged.run(runner.as_ref()).await });
        backend.sa_applied.notified().await;
        handle.abort();
        assert!(handle.await.is_err());
        drop(gate);

        // The backend applied the SA but the acknowledgement was never
        // observed: exact SA recovery authority must be retained.
        assert_eq!(journal.ownership(), XfrmInstallOwnership::SaInFlight);
        let plan = journal.recovery_plan();
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), None);

        journal
            .recover(backend.as_ref())
            .await
            .expect("recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(backend.operations(), vec!["install_sa", "remove_sa"]);
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
        assert!(backend.sas().is_empty());
    }

    #[tokio::test]
    async fn recover_rejected_while_run_in_flight_then_succeeds_after_abort() {
        let backend = GatedBackend {
            policy_gate_mode: Some(GateMode::BeforeApply),
            ..GatedBackend::new()
        };
        let gate = backend.gate_policy();
        let backend = Arc::new(backend);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = backend.clone();
        let handle = tokio::spawn(async move { staged.run(runner.as_ref()).await });
        backend.policy_started.notified().await;

        // The runner is still live: recovery must not retire removal
        // authority the runner may still need.
        let error = journal
            .recover(backend.as_ref())
            .await
            .expect_err("recovery during a live run is rejected");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        assert_eq!(journal.ownership(), XfrmInstallOwnership::PolicyInFlight);

        // Dropping the runner finishes it; recovery then proceeds normally.
        handle.abort();
        assert!(handle.await.is_err());
        drop(gate);
        journal
            .recover(backend.as_ref())
            .await
            .expect("recovery succeeds after the runner finished");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert!(backend.sas().is_empty());
        assert!(backend.policies().is_empty());
    }

    #[tokio::test]
    async fn recover_rejected_before_runner_is_polled() {
        let backend = GatedBackend::new();

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();

        let error = journal
            .recover(&backend)
            .await
            .expect_err("recovery before the runner started is rejected");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        assert_eq!(journal.ownership(), XfrmInstallOwnership::NotStarted);
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_sa_before_policy_completion_retains_exact_recovery() {
        let backend = GatedBackend {
            policy_gate_mode: Some(GateMode::BeforeApply),
            ..GatedBackend::new()
        };
        let gate = backend.gate_policy();
        let backend = Arc::new(backend);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = backend.clone();
        let handle = tokio::spawn(async move { staged.run(runner.as_ref()).await });
        backend.policy_started.notified().await;
        handle.abort();
        assert!(handle.await.is_err());
        drop(gate);

        // The SA is owned; the policy was issued but never observed, so exact
        // authority for both is retained.
        assert_eq!(journal.ownership(), XfrmInstallOwnership::PolicyInFlight);
        let plan = journal.recovery_plan();
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), Some(&expected_remove_policy()));
        assert!(!plan.requires_readback());

        journal
            .recover(backend.as_ref())
            .await
            .expect("recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        // The policy was never applied: `NotFound` is idempotent success.
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_policy", "remove_sa"]
        );
        assert_eq!(
            backend.removed_policy_requests(),
            vec![expected_remove_policy()]
        );
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
        assert!(backend.sas().is_empty());
        assert!(backend.policies().is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_policy_applied_before_return_retains_exact_recovery() {
        let backend = GatedBackend {
            policy_gate_mode: Some(GateMode::AfterApply),
            ..GatedBackend::new()
        };
        let gate = backend.gate_policy();
        let backend = Arc::new(backend);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = backend.clone();
        let handle = tokio::spawn(async move { staged.run(runner.as_ref()).await });
        backend.policy_applied.notified().await;
        handle.abort();
        assert!(handle.await.is_err());
        drop(gate);

        // The backend applied the policy but the acknowledgement was never
        // observed; the journal still retains exact authority for both.
        assert_eq!(journal.ownership(), XfrmInstallOwnership::PolicyInFlight);
        let plan = journal.recovery_plan();
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), Some(&expected_remove_policy()));

        journal
            .recover(backend.as_ref())
            .await
            .expect("recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_policy", "remove_sa"]
        );
        assert!(backend.sas().is_empty());
        assert!(backend.policies().is_empty());
    }

    #[tokio::test]
    async fn already_exists_sa_install_does_not_remove_existing_sa() {
        let backend = GatedBackend::new();
        backend.preinstall_sa(expected_remove_sa());

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("pre-existing SA fails the install");

        assert!(matches!(
            error,
            XfrmCompositeInstallError::InstallSaFailed {
                source: XfrmError::AlreadyExists,
                ..
            }
        ));
        assert_eq!(
            error.outcome(),
            XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa)
        );
        assert_eq!(journal.ownership(), XfrmInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());

        journal
            .recover(&backend)
            .await
            .expect("empty recovery succeeds");
        assert_eq!(backend.operations(), vec!["install_sa"]);
        // The pre-existing SA is not owned and is never removed.
        assert_eq!(backend.sas(), vec![expected_remove_sa()]);
        assert!(backend.removed_sa_requests().is_empty());
    }

    #[tokio::test]
    async fn already_exists_policy_install_rolls_back_only_the_new_sa() {
        let backend = GatedBackend::new();
        backend.preinstall_policy(expected_remove_policy());

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("pre-existing policy fails the install");

        assert!(matches!(
            error,
            XfrmCompositeInstallError::PolicyInstallRolledBack {
                source: XfrmError::AlreadyExists,
                ..
            }
        ));
        assert_eq!(
            error.outcome(),
            XfrmCompositeOutcome::rolled_back(XfrmCompositeOperation::InstallPolicy)
        );
        // Only the newly acquired SA was rolled back.
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_sa"]
        );
        assert!(backend.sas().is_empty());
        assert_eq!(backend.policies(), vec![expected_remove_policy()]);
        assert!(backend.removed_policy_requests().is_empty());

        assert_eq!(journal.ownership(), XfrmInstallOwnership::RolledBack);
        assert!(journal.recovery_plan().is_empty());
        journal
            .recover(&backend)
            .await
            .expect("empty recovery succeeds");
        assert_eq!(backend.policies(), vec![expected_remove_policy()]);
    }

    #[tokio::test]
    async fn fully_rolled_back_failure_reports_no_residual_ownership() {
        let backend = GatedBackend {
            install_policy_error: Some(XfrmError::Unavailable),
            ..GatedBackend::new()
        };

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("policy failure rolls back");

        assert_eq!(error.as_str(), "xfrm_composite_policy_install_rolled_back");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::RolledBack);
        assert!(!journal.ownership().has_residue());
        assert!(journal.recovery_plan().is_empty());

        journal
            .recover(&backend)
            .await
            .expect("empty recovery succeeds");
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_sa"]
        );
    }

    #[tokio::test]
    async fn rollback_failure_stays_typed_and_keeps_exact_sa_residue_recoverable() {
        let backend = GatedBackend {
            install_policy_error: Some(XfrmError::Unavailable),
            ..GatedBackend::new()
        };
        backend.fail_remove_sa(XfrmError::Unavailable);

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("rollback failure is reported");

        // The rollback failure is not collapsed into a generic error.
        assert_eq!(
            error.as_str(),
            "xfrm_composite_policy_install_rollback_failed"
        );
        match &error {
            XfrmCompositeInstallError::PolicyInstallRollbackFailed {
                source,
                rollback,
                outcome,
            } => {
                assert!(matches!(source, XfrmError::Unavailable));
                assert!(matches!(rollback, XfrmError::Unavailable));
                assert!(outcome.rollback_failed);
                assert!(outcome.partial_state_possible);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Exact SA residue is still owned and recoverable; the definitively
        // rejected policy is not part of the plan.
        assert_eq!(journal.ownership(), XfrmInstallOwnership::SaAcquired);
        let plan = journal.recovery_plan();
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), None);

        backend.clear_remove_sa_error();
        journal
            .recover(&backend)
            .await
            .expect("recovery retry succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_sa", "remove_sa"]
        );
        assert!(backend.sas().is_empty());
    }

    #[tokio::test]
    async fn indeterminate_sa_install_stays_explicitly_recoverable() {
        let backend = GatedBackend {
            install_sa_error: Some(XfrmError::StateIndeterminate {
                operation: "install_sa_readback",
            }),
            ..GatedBackend::new()
        };

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("indeterminate SA install is reported");

        assert!(matches!(
            error,
            XfrmCompositeInstallError::InstallSaFailed {
                source: XfrmError::StateIndeterminate { .. },
                ..
            }
        ));
        assert_eq!(
            error.outcome(),
            XfrmCompositeOutcome::indeterminate(XfrmCompositeOperation::InstallSa)
        );

        assert_eq!(
            journal.ownership(),
            XfrmInstallOwnership::Indeterminate {
                operation: XfrmCompositeOperation::InstallSa
            }
        );
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert_eq!(plan.policy(), None);

        journal
            .recover(&backend)
            .await
            .expect("classified recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
    }

    #[tokio::test]
    async fn indeterminate_policy_install_keeps_policy_residue_recoverable() {
        let backend = GatedBackend {
            install_policy_error: Some(XfrmError::StateIndeterminate {
                operation: "install_policy_readback",
            }),
            ..GatedBackend::new()
        };

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("indeterminate policy install is reported");

        assert!(matches!(
            error,
            XfrmCompositeInstallError::PolicyInstallRolledBack {
                source: XfrmError::StateIndeterminate { .. },
                ..
            }
        ));

        // The helper rolled its acknowledged SA back, but the policy mutation
        // may have been accepted: exact policy residue stays recoverable and
        // classified as readback-requiring instead of collapsing into a
        // generic error.
        assert_eq!(
            journal.ownership(),
            XfrmInstallOwnership::Indeterminate {
                operation: XfrmCompositeOperation::InstallPolicy
            }
        );
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert_eq!(plan.policy(), Some(&expected_remove_policy()));
        assert_eq!(plan.sa(), None);

        journal
            .recover(&backend)
            .await
            .expect("classified recovery succeeds");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert_eq!(
            backend.removed_policy_requests(),
            vec![expected_remove_policy()]
        );
    }

    #[tokio::test]
    async fn recovery_retry_is_idempotent_for_not_found_without_broadening_identity() {
        let backend = GatedBackend::new();

        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let outcome = staged.run(&backend).await.expect("install applies");
        assert_eq!(outcome, XfrmCompositeOutcome::applied());
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Complete);

        // Residue is removed externally before recovery runs.
        backend
            .remove_policy(expected_remove_policy())
            .await
            .expect("external policy removal");
        backend
            .remove_sa(expected_remove_sa())
            .await
            .expect("external SA removal");

        journal
            .recover(&backend)
            .await
            .expect("NotFound is idempotent success");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);

        // Every removal the journal authorized used the exact retained
        // identity; nothing was broadened.
        assert_eq!(
            backend.removed_policy_requests(),
            vec![expected_remove_policy(), expected_remove_policy()]
        );
        assert_eq!(
            backend.removed_sa_requests(),
            vec![expected_remove_sa(), expected_remove_sa()]
        );

        // Retrying a completed recovery is a no-op.
        let operations_before = backend.operations().len();
        journal
            .recover(&backend)
            .await
            .expect("recovery retry is a no-op");
        assert_eq!(backend.operations().len(), operations_before);
    }

    #[tokio::test]
    async fn staged_outcome_error_and_debug_surfaces_are_redaction_safe() {
        let mut request = install_request();
        request.sa.parameters.auth = Some((
            crate::AuthAlgorithm::hmac_sha256(96),
            crate::KeyMaterial::new(vec![0xab; 32]),
        ));
        request.sa.parameters.crypt = Some((
            crate::Algorithm::cbc_aes(),
            crate::KeyMaterial::new(vec![0xcd; 32]),
        ));

        let backend = GatedBackend {
            install_policy_error: Some(XfrmError::Unavailable),
            ..GatedBackend::new()
        };
        backend.fail_remove_sa(XfrmError::Unavailable);

        let staged = XfrmStagedInstall::new(request);
        let journal = staged.journal();
        let error = staged
            .run(&backend)
            .await
            .expect_err("rollback failure is reported");
        let recovery_error = journal
            .recover(&backend)
            .await
            .expect_err("recovery failure is reported");

        let surfaces = [
            format!("{error:?}"),
            error.to_string(),
            format!("{:?}", error.outcome()),
            format!("{:?}", journal.ownership()),
            format!("{:?}", journal.recovery_plan()),
            format!("{journal:?}"),
            format!("{staged:?}"),
            format!("{recovery_error:?}"),
            recovery_error.to_string(),
        ];
        for surface in &surfaces {
            assert!(
                !surface.contains("171") && !surface.contains("205"),
                "surface leaked key material: {surface}"
            );
            assert!(
                !surface.contains("0xab") && !surface.contains("0xcd"),
                "surface leaked key material: {surface}"
            );
        }
        // Error displays remain stable machine-readable labels only.
        assert_eq!(
            error.to_string(),
            "xfrm_composite_policy_install_rollback_failed"
        );
        assert_eq!(
            recovery_error.to_string(),
            "xfrm_install_recovery_remove_sa_failed"
        );
    }
}
