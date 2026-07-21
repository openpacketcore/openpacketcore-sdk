//! Cancellation-safe staged composite XFRM installation.
//!
//! [`XfrmStagedInstall`] is affine: calling [`XfrmStagedInstall::run`]
//! consumes the staged value, so safe Rust cannot start the same mutation
//! sequence twice. A caller clones [`XfrmInstallJournal`] before starting the
//! runner. On first poll, the runner moves into an owned Tokio worker; dropping
//! its observing future cannot cancel an adapter's detached `spawn_blocking`
//! mutation or make recovery race that mutation. The journal records
//! acknowledged mutations and unobserved backend results, and remains
//! available if the observer is dropped.
//!
//! Destructive recovery is deliberately explicit. A caller obtains the
//! current [`XfrmInstallRecoveryPlan`], classifies every exact candidate as
//! [`XfrmResidueClassification::Owned`], `Absent`, `Foreign`, or
//! `Indeterminate`, and passes the generation-bound classification to
//! [`XfrmInstallJournal::recover`]. Recovery is supervised by the same rule:
//! dropping its observer leaves the owned worker and recovery claim live until
//! every issued removal returns. Unobserved results never become blind deletion
//! authority. If either owned worker terminates abnormally, the journal records
//! supervision loss and permanently disables in-process recovery: a detached
//! blocking syscall may still complete after the async worker is gone. A fresh
//! process must re-establish namespace-wide exclusion and authoritative state
//! before deciding how to handle residue. Classification must be performed
//! while the caller holds the product's namespace-wide XFRM writer exclusion;
//! exact readback alone cannot distinguish an identical foreign replacement.

use std::{
    error::Error,
    fmt,
    future::Future,
    sync::{Arc, Mutex},
};

use crate::{
    outbound_binding::{validate_outbound_request, OutboundSaPolicyExpectation},
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend, OutboundSaBindingError,
    RemovePolicyRequest, RemoveSaRequest, XfrmBackend, XfrmCompositeInstallError,
    XfrmCompositeInstallRequest, XfrmCompositeOperation, XfrmCompositeOutcome, XfrmError,
};

/// XFRM object represented by a recovery classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmInstallObject {
    /// Security Association.
    Sa,
    /// Security Policy.
    Policy,
}

impl XfrmInstallObject {
    /// Stable machine-readable object label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sa => "sa",
            Self::Policy => "policy",
        }
    }
}

/// Set of backend operations whose final state was not observed.
///
/// The set contains operation labels only and is safe to format in logs.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct XfrmIndeterminateOperations {
    bits: u16,
}

impl XfrmIndeterminateOperations {
    const INSTALL_SA: u16 = 1 << 0;
    const INSTALL_POLICY: u16 = 1 << 1;
    const ROLLBACK_REMOVE_SA: u16 = 1 << 2;
    const REMOVE_POLICY: u16 = 1 << 3;
    const REMOVE_SA: u16 = 1 << 4;

    const fn bit(operation: XfrmCompositeOperation) -> u16 {
        match operation {
            XfrmCompositeOperation::InstallSa => Self::INSTALL_SA,
            XfrmCompositeOperation::InstallPolicy => Self::INSTALL_POLICY,
            XfrmCompositeOperation::RollbackRemoveSa => Self::ROLLBACK_REMOVE_SA,
            XfrmCompositeOperation::RemovePolicy => Self::REMOVE_POLICY,
            XfrmCompositeOperation::RemoveSa => Self::REMOVE_SA,
            XfrmCompositeOperation::RekeySa | XfrmCompositeOperation::RekeyPolicy => 0,
        }
    }

    fn insert(&mut self, operation: XfrmCompositeOperation) {
        self.bits |= Self::bit(operation);
    }

    fn clear_sa(&mut self) {
        self.bits &= !(Self::INSTALL_SA | Self::ROLLBACK_REMOVE_SA | Self::REMOVE_SA);
    }

    fn clear_policy(&mut self) {
        self.bits &= !(Self::INSTALL_POLICY | Self::REMOVE_POLICY);
    }

    /// True when no operation is indeterminate.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// True when `operation` is in the set.
    pub const fn contains(self, operation: XfrmCompositeOperation) -> bool {
        self.bits & Self::bit(operation) != 0
    }

    /// Iterate over the indeterminate operation labels in execution order.
    pub fn iter(self) -> impl Iterator<Item = XfrmCompositeOperation> {
        [
            XfrmCompositeOperation::InstallSa,
            XfrmCompositeOperation::InstallPolicy,
            XfrmCompositeOperation::RollbackRemoveSa,
            XfrmCompositeOperation::RemovePolicy,
            XfrmCompositeOperation::RemoveSa,
        ]
        .into_iter()
        .filter(move |operation| self.contains(*operation))
    }
}

impl fmt::Debug for XfrmIndeterminateOperations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(XfrmCompositeOperation::as_str))
            .finish()
    }
}

/// Typed mutation ownership of a staged composite install.
///
/// Variants carry only stable labels. Exact identities remain available from
/// [`XfrmInstallRecoveryPlan`] and are omitted from its `Debug` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmInstallOwnership {
    /// The runner has not acquired or issued a mutation.
    NotStarted,
    /// The SA install is currently in flight.
    SaInFlight,
    /// Only SA residue may remain.
    SaAcquired,
    /// The policy install is currently in flight after SA acknowledgement.
    PolicyInFlight,
    /// Only policy residue may remain.
    PolicyAcquired,
    /// Both SA and policy were acknowledged.
    Complete,
    /// The runner rolled back every candidate it owned.
    RolledBack,
    /// Classified recovery is currently issuing this removal.
    Recovering {
        /// Removal operation in flight.
        operation: XfrmCompositeOperation,
    },
    /// Recovery cleared every candidate by exact removal or classification.
    Recovered,
    /// The caller committed the acknowledged install and retired every journal
    /// cleanup authority. Product teardown now owns the installed state.
    Committed,
    /// One or more backend results were not observed.
    Indeterminate {
        /// Complete set of unobserved operations.
        operations: XfrmIndeterminateOperations,
    },
    /// The owned Tokio worker terminated abnormally while an adapter may still
    /// have detached blocking work in flight.
    ///
    /// This permanently disables in-process recovery for the journal. A fresh
    /// process must re-establish namespace-wide exclusion and authoritative
    /// readback before deciding how to handle any residue.
    SupervisionLost {
        /// Operation that was in flight when supervision was lost, when known.
        operation: Option<XfrmCompositeOperation>,
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
            Self::PolicyAcquired => "policy_acquired",
            Self::Complete => "complete",
            Self::RolledBack => "rolled_back",
            Self::Recovering { .. } => "recovering",
            Self::Recovered => "recovered",
            Self::Committed => "committed",
            Self::Indeterminate { .. } => "indeterminate",
            Self::SupervisionLost { .. } => "supervision_lost",
        }
    }

    /// True when this operation may still own backend residue.
    pub const fn has_residue(self) -> bool {
        matches!(
            self,
            Self::SaInFlight
                | Self::SaAcquired
                | Self::PolicyInFlight
                | Self::PolicyAcquired
                | Self::Complete
                | Self::Recovering { .. }
                | Self::Indeterminate { .. }
                | Self::SupervisionLost { .. }
        )
    }
}

/// Result of classifying one exact recovery candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmResidueClassification {
    /// The caller proved that the exact object is owned by this staged install.
    Owned,
    /// Exact readback proved that the object is absent.
    Absent,
    /// Readback or ownership metadata proved that the object belongs to a
    /// different operation. Recovery retires the candidate without deleting it.
    Foreign,
    /// Ownership remains indeterminate. Recovery fails closed without mutation.
    Indeterminate,
}

/// Generation-bound classification for an exact recovery plan.
///
/// Construct this value with [`XfrmInstallRecoveryPlan::classification`]. A
/// classification becomes stale whenever runner or recovery state changes.
#[derive(Clone)]
pub struct XfrmInstallRecoveryClassification {
    generation: Arc<()>,
    policy: Option<XfrmResidueClassification>,
    sa: Option<XfrmResidueClassification>,
}

impl XfrmInstallRecoveryClassification {
    /// Classify the policy candidate in the originating plan.
    #[must_use]
    pub fn with_policy(mut self, classification: XfrmResidueClassification) -> Self {
        self.policy = Some(classification);
        self
    }

    /// Classify the SA candidate in the originating plan.
    #[must_use]
    pub fn with_sa(mut self, classification: XfrmResidueClassification) -> Self {
        self.sa = Some(classification);
        self
    }
}

impl fmt::Debug for XfrmInstallRecoveryClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmInstallRecoveryClassification")
            .field("policy", &self.policy)
            .field("sa", &self.sa)
            .finish_non_exhaustive()
    }
}

/// Exact removal candidates retained for staged-install residue.
///
/// `Debug` reports only candidate presence and operation labels; use the
/// accessors when privileged recovery code needs the exact identity.
#[derive(Clone)]
pub struct XfrmInstallRecoveryPlan {
    policy: Option<RemovePolicyRequest>,
    sa: Option<RemoveSaRequest>,
    uncertainties: XfrmIndeterminateOperations,
    supervision_lost: bool,
    generation: Arc<()>,
}

impl XfrmInstallRecoveryPlan {
    /// True when no candidate remains.
    pub const fn is_empty(&self) -> bool {
        self.policy.is_none() && self.sa.is_none()
    }

    /// Exact policy candidate, when one remains.
    pub const fn policy(&self) -> Option<&RemovePolicyRequest> {
        self.policy.as_ref()
    }

    /// Exact SA candidate, when one remains.
    pub const fn sa(&self) -> Option<&RemoveSaRequest> {
        self.sa.as_ref()
    }

    /// Operations whose final result was not observed.
    pub const fn indeterminate_operations(&self) -> XfrmIndeterminateOperations {
        self.uncertainties
    }

    /// True when an owned async worker terminated abnormally and in-process
    /// recovery is permanently disabled for this journal.
    pub const fn supervision_lost(&self) -> bool {
        self.supervision_lost
    }

    /// True when exact readback and writer-fence classification is required
    /// because at least one backend result was not observed.
    pub const fn requires_readback(&self) -> bool {
        self.supervision_lost || !self.uncertainties.is_empty()
    }

    /// True when recovery requires a classification value.
    pub const fn requires_classification(&self) -> bool {
        !self.is_empty()
    }

    /// Start a generation-bound classification for this exact plan.
    #[must_use]
    pub fn classification(&self) -> XfrmInstallRecoveryClassification {
        XfrmInstallRecoveryClassification {
            generation: self.generation.clone(),
            policy: None,
            sa: None,
        }
    }
}

impl fmt::Debug for XfrmInstallRecoveryPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmInstallRecoveryPlan")
            .field("policy_candidate", &self.policy.is_some())
            .field("sa_candidate", &self.sa.is_some())
            .field("indeterminate_operations", &self.uncertainties)
            .field("supervision_lost", &self.supervision_lost)
            .finish_non_exhaustive()
    }
}

impl PartialEq for XfrmInstallRecoveryPlan {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.sa == other.sa
            && self.uncertainties == other.uncertainties
            && self.supervision_lost == other.supervision_lost
            && Arc::ptr_eq(&self.generation, &other.generation)
    }
}

impl Eq for XfrmInstallRecoveryPlan {}

/// Error returned by [`XfrmInstallJournal::commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmInstallCommitError {
    /// The runner was never started or remains live.
    RunnerNotFinished,
    /// Classified recovery is currently live.
    RecoveryInProgress,
    /// The install is not a fully acknowledged SA-plus-policy pair.
    NotComplete,
    /// Unobserved backend results must be classified before ownership transfer.
    Indeterminate,
    /// Recovery already retired the journal's candidates.
    AlreadyRecovered,
}

impl XfrmInstallCommitError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunnerNotFinished => "xfrm_install_commit_runner_not_finished",
            Self::RecoveryInProgress => "xfrm_install_commit_recovery_in_progress",
            Self::NotComplete => "xfrm_install_commit_not_complete",
            Self::Indeterminate => "xfrm_install_commit_indeterminate",
            Self::AlreadyRecovered => "xfrm_install_commit_already_recovered",
        }
    }
}

impl fmt::Display for XfrmInstallCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmInstallCommitError {}

/// Error returned by the supervised [`XfrmStagedInstall::run`] worker.
#[derive(Debug, Clone)]
pub enum XfrmStagedInstallRunError {
    /// The staged composite operation returned its typed protocol error.
    Composite {
        /// Redaction-safe composite error.
        source: XfrmCompositeInstallError,
    },
    /// The future was first polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// The supervised worker terminated without returning an operation result.
    ///
    /// The journal records permanent supervision loss because adapter-owned
    /// blocking work may outlive the async worker. In-process recovery remains
    /// disabled for that journal.
    WorkerTerminated,
}

impl XfrmStagedInstallRunError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Composite { source } => source.as_str(),
            Self::RuntimeUnavailable => "xfrm_staged_install_runtime_unavailable",
            Self::WorkerTerminated => "xfrm_staged_install_worker_terminated",
        }
    }

    /// Composite outcome evidence, when the worker returned an operation
    /// error rather than terminating unexpectedly.
    pub const fn outcome(&self) -> Option<XfrmCompositeOutcome> {
        match self {
            Self::Composite { source } => Some(source.outcome()),
            Self::RuntimeUnavailable | Self::WorkerTerminated => None,
        }
    }
}

impl fmt::Display for XfrmStagedInstallRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmStagedInstallRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Composite { source } => Some(source),
            Self::RuntimeUnavailable | Self::WorkerTerminated => None,
        }
    }
}

impl From<XfrmCompositeInstallError> for XfrmStagedInstallRunError {
    fn from(source: XfrmCompositeInstallError) -> Self {
        Self::Composite { source }
    }
}

/// Error returned by [`XfrmInstallJournal::recover`].
#[derive(Debug, Clone)]
pub enum XfrmInstallRecoveryError {
    /// Policy removal failed.
    RemovePolicyFailed {
        /// Redaction-safe backend error.
        source: XfrmError,
    },
    /// SA removal failed.
    RemoveSaFailed {
        /// Redaction-safe backend error.
        source: XfrmError,
    },
    /// The install runner was never started or remains live.
    RunnerNotFinished,
    /// Another recovery future owns the recovery claim.
    RecoveryInProgress,
    /// The recovery future was first polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// The supervised recovery worker terminated without returning a result.
    /// In-process recovery remains permanently disabled for this journal.
    WorkerTerminated,
    /// The install was committed to product ownership.
    Committed,
    /// The classification was created from an older plan generation.
    StaleClassification,
    /// A candidate had no classification.
    MissingClassification {
        /// Candidate lacking classification.
        object: XfrmInstallObject,
    },
    /// A classification was supplied for an object absent from the plan.
    UnexpectedClassification {
        /// Unexpected classified object.
        object: XfrmInstallObject,
    },
    /// The caller reported that ownership remains indeterminate.
    ClassificationIndeterminate {
        /// Candidate that remains indeterminate.
        object: XfrmInstallObject,
    },
}

impl XfrmInstallRecoveryError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RemovePolicyFailed { .. } => "xfrm_install_recovery_remove_policy_failed",
            Self::RemoveSaFailed { .. } => "xfrm_install_recovery_remove_sa_failed",
            Self::RunnerNotFinished => "xfrm_install_recovery_runner_not_finished",
            Self::RecoveryInProgress => "xfrm_install_recovery_in_progress",
            Self::RuntimeUnavailable => "xfrm_install_recovery_runtime_unavailable",
            Self::WorkerTerminated => "xfrm_install_recovery_worker_terminated",
            Self::Committed => "xfrm_install_recovery_committed",
            Self::StaleClassification => "xfrm_install_recovery_stale_classification",
            Self::MissingClassification { .. } => "xfrm_install_recovery_missing_classification",
            Self::UnexpectedClassification { .. } => {
                "xfrm_install_recovery_unexpected_classification"
            }
            Self::ClassificationIndeterminate { .. } => {
                "xfrm_install_recovery_classification_indeterminate"
            }
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
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    NotStarted,
    SaAcquired,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunLifecycle {
    NotStarted,
    Running,
    Finished,
}

struct JournalState {
    stage: Stage,
    lifecycle: RunLifecycle,
    runner_inflight: Option<XfrmCompositeOperation>,
    recovery_inflight: Option<XfrmCompositeOperation>,
    recovery_running: bool,
    runner_supervision_lost: bool,
    recovery_supervision_lost: bool,
    sa_possible: bool,
    policy_possible: bool,
    rolled_back: bool,
    recovered: bool,
    committed: bool,
    uncertainties: XfrmIndeterminateOperations,
    generation: Arc<()>,
}

impl JournalState {
    fn new() -> Self {
        Self {
            stage: Stage::NotStarted,
            lifecycle: RunLifecycle::NotStarted,
            runner_inflight: None,
            recovery_inflight: None,
            recovery_running: false,
            runner_supervision_lost: false,
            recovery_supervision_lost: false,
            sa_possible: false,
            policy_possible: false,
            rolled_back: false,
            recovered: false,
            committed: false,
            uncertainties: XfrmIndeterminateOperations::default(),
            generation: Arc::new(()),
        }
    }

    fn touch(&mut self) {
        self.generation = Arc::new(());
    }

    fn mark_indeterminate(&mut self, operation: XfrmCompositeOperation) {
        self.uncertainties.insert(operation);
        self.touch();
    }

    fn clear_sa(&mut self) {
        self.sa_possible = false;
        self.uncertainties.clear_sa();
        self.touch();
    }

    fn clear_policy(&mut self) {
        self.policy_possible = false;
        self.uncertainties.clear_policy();
        self.touch();
    }

    fn ownership(&self) -> XfrmInstallOwnership {
        if self.committed {
            return XfrmInstallOwnership::Committed;
        }
        if self.recovered {
            return XfrmInstallOwnership::Recovered;
        }
        if self.recovery_supervision_lost {
            return XfrmInstallOwnership::SupervisionLost {
                operation: self.recovery_inflight,
            };
        }
        if self.runner_supervision_lost {
            return XfrmInstallOwnership::SupervisionLost {
                operation: self.runner_inflight,
            };
        }
        if let Some(operation) = self.recovery_inflight {
            return XfrmInstallOwnership::Recovering { operation };
        }
        if !self.uncertainties.is_empty() {
            return XfrmInstallOwnership::Indeterminate {
                operations: self.uncertainties,
            };
        }
        match self.runner_inflight {
            Some(XfrmCompositeOperation::InstallSa) => return XfrmInstallOwnership::SaInFlight,
            Some(XfrmCompositeOperation::InstallPolicy) => {
                return XfrmInstallOwnership::PolicyInFlight;
            }
            _ => {}
        }
        match (self.sa_possible, self.policy_possible) {
            (true, true) => XfrmInstallOwnership::Complete,
            (true, false) => XfrmInstallOwnership::SaAcquired,
            (false, true) => XfrmInstallOwnership::PolicyAcquired,
            (false, false) if self.rolled_back => XfrmInstallOwnership::RolledBack,
            (false, false) => XfrmInstallOwnership::NotStarted,
        }
    }

    fn plan(&self, inner: &JournalInner) -> XfrmInstallRecoveryPlan {
        let terminal = self.committed || self.recovered;
        XfrmInstallRecoveryPlan {
            policy: (!terminal && self.policy_possible).then(|| inner.remove_policy.clone()),
            sa: (!terminal && self.sa_possible).then_some(inner.remove_sa),
            uncertainties: if terminal {
                XfrmIndeterminateOperations::default()
            } else {
                self.uncertainties
            },
            supervision_lost: !terminal
                && (self.runner_supervision_lost || self.recovery_supervision_lost),
            generation: self.generation.clone(),
        }
    }
}

struct JournalInner {
    remove_sa: RemoveSaRequest,
    remove_policy: RemovePolicyRequest,
    state: Mutex<JournalState>,
}

/// Caller-visible staged-install mutation journal.
#[derive(Clone)]
pub struct XfrmInstallJournal {
    inner: Arc<JournalInner>,
}

impl fmt::Debug for XfrmInstallJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        let plan = state.plan(&self.inner);
        f.debug_struct("XfrmInstallJournal")
            .field("ownership", &state.ownership())
            .field("recovery_plan", &plan)
            .finish()
    }
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

    /// Current typed mutation ownership.
    pub fn ownership(&self) -> XfrmInstallOwnership {
        self.state().ownership()
    }

    /// Current exact, generation-bound recovery plan.
    pub fn recovery_plan(&self) -> XfrmInstallRecoveryPlan {
        self.state().plan(&self.inner)
    }

    /// Commit a fully acknowledged install to product ownership.
    ///
    /// Every journal clone observes the resulting
    /// [`XfrmInstallOwnership::Committed`] state, and no clone can subsequently
    /// invoke journal recovery. Product teardown must use its own authoritative
    /// installed-object record after this transfer.
    pub fn commit(&self) -> Result<(), XfrmInstallCommitError> {
        let mut state = self.state();
        if state.committed {
            return Ok(());
        }
        if state.lifecycle != RunLifecycle::Finished {
            return Err(XfrmInstallCommitError::RunnerNotFinished);
        }
        if state.runner_supervision_lost || state.recovery_supervision_lost {
            return Err(XfrmInstallCommitError::Indeterminate);
        }
        if state.recovery_running {
            return Err(XfrmInstallCommitError::RecoveryInProgress);
        }
        if state.recovered {
            return Err(XfrmInstallCommitError::AlreadyRecovered);
        }
        if !state.uncertainties.is_empty() {
            return Err(XfrmInstallCommitError::Indeterminate);
        }
        if state.stage != Stage::Complete || !state.sa_possible || !state.policy_possible {
            return Err(XfrmInstallCommitError::NotComplete);
        }
        state.committed = true;
        state.touch();
        Ok(())
    }

    fn issue_outbound_binding(
        &self,
        backend: &NamespaceBoundLinuxXfrmBackend,
        expectation: OutboundSaPolicyExpectation,
    ) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
        if self.ownership() != XfrmInstallOwnership::Committed {
            return Err(OutboundSaBindingError::Commit {
                source: XfrmInstallCommitError::NotComplete,
            });
        }
        Ok(InstalledOutboundSaBinding::new(
            backend.network_namespace_binding(),
            expectation,
        ))
    }

    /// Apply a generation-bound, exact recovery classification.
    ///
    /// Every candidate must be classified. `Owned` issues the exact retained
    /// removal, `Absent` and `Foreign` retire the candidate without mutation,
    /// and `Indeterminate` fails closed. Classification is evidence supplied by
    /// the product while holding namespace-wide writer exclusion; callers must
    /// not infer `Owned` merely from install intent or matching readback.
    ///
    /// Only one recovery worker can run at a time. Once the returned future is
    /// polled, dropping it detaches only the observer; its owned worker keeps
    /// the recovery claim until every issued backend removal returns. If the
    /// worker itself terminates while a removal may be in flight, the journal
    /// records permanent supervision loss and rejects every later in-process
    /// recovery attempt.
    pub fn recover<B>(
        &self,
        backend: Arc<B>,
        classification: XfrmInstallRecoveryClassification,
    ) -> impl Future<Output = Result<(), XfrmInstallRecoveryError>> + Send + 'static
    where
        B: XfrmBackend + ?Sized + 'static,
    {
        let journal = self.clone();
        async move {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| XfrmInstallRecoveryError::RuntimeUnavailable)?;
            let worker = runtime.spawn(async move {
                journal
                    .recover_inner(backend.as_ref(), classification)
                    .await
            });
            match worker.await {
                Ok(result) => result,
                Err(_) => Err(XfrmInstallRecoveryError::WorkerTerminated),
            }
        }
    }

    async fn recover_inner<B>(
        &self,
        backend: &B,
        classification: XfrmInstallRecoveryClassification,
    ) -> Result<(), XfrmInstallRecoveryError>
    where
        B: XfrmBackend + ?Sized,
    {
        let (plan, policy_classification, sa_classification) = {
            let mut state = self.state();
            if state.runner_supervision_lost || state.recovery_supervision_lost {
                return Err(XfrmInstallRecoveryError::WorkerTerminated);
            }
            if state.lifecycle != RunLifecycle::Finished {
                return Err(XfrmInstallRecoveryError::RunnerNotFinished);
            }
            if state.committed {
                return Err(XfrmInstallRecoveryError::Committed);
            }
            if state.recovered {
                return Ok(());
            }
            if state.recovery_running {
                return Err(XfrmInstallRecoveryError::RecoveryInProgress);
            }
            if !Arc::ptr_eq(&classification.generation, &state.generation) {
                return Err(XfrmInstallRecoveryError::StaleClassification);
            }
            let plan = state.plan(&self.inner);
            let policy_classification = validate_classification(
                plan.policy.is_some(),
                classification.policy,
                XfrmInstallObject::Policy,
            )?;
            let sa_classification = validate_classification(
                plan.sa.is_some(),
                classification.sa,
                XfrmInstallObject::Sa,
            )?;
            state.recovery_running = true;
            state.touch();
            (plan, policy_classification, sa_classification)
        };

        let mut guard = RecoveryGuard::new(self.clone());
        let result = async {
            if let (Some(request), Some(classification)) = (plan.policy, policy_classification) {
                match classification {
                    XfrmResidueClassification::Absent | XfrmResidueClassification::Foreign => {
                        self.state().clear_policy();
                    }
                    XfrmResidueClassification::Owned => {
                        {
                            let mut state = self.state();
                            state.uncertainties.clear_policy();
                            state.recovery_inflight = Some(XfrmCompositeOperation::RemovePolicy);
                            state.touch();
                        }
                        match backend.remove_policy(request).await {
                            Ok(()) | Err(XfrmError::NotFound) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                state.clear_policy();
                            }
                            Err(source) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                if matches!(&source, XfrmError::StateIndeterminate { .. }) {
                                    state.mark_indeterminate(XfrmCompositeOperation::RemovePolicy);
                                } else {
                                    state.touch();
                                }
                                return Err(XfrmInstallRecoveryError::RemovePolicyFailed {
                                    source,
                                });
                            }
                        }
                    }
                    XfrmResidueClassification::Indeterminate => {
                        return Err(XfrmInstallRecoveryError::ClassificationIndeterminate {
                            object: XfrmInstallObject::Policy,
                        });
                    }
                }
            }

            if let (Some(request), Some(classification)) = (plan.sa, sa_classification) {
                match classification {
                    XfrmResidueClassification::Absent | XfrmResidueClassification::Foreign => {
                        self.state().clear_sa();
                    }
                    XfrmResidueClassification::Owned => {
                        {
                            let mut state = self.state();
                            state.uncertainties.clear_sa();
                            state.recovery_inflight = Some(XfrmCompositeOperation::RemoveSa);
                            state.touch();
                        }
                        match backend.remove_sa(request).await {
                            Ok(()) | Err(XfrmError::NotFound) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                state.clear_sa();
                            }
                            Err(source) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                if matches!(&source, XfrmError::StateIndeterminate { .. }) {
                                    state.mark_indeterminate(XfrmCompositeOperation::RemoveSa);
                                } else {
                                    state.touch();
                                }
                                return Err(XfrmInstallRecoveryError::RemoveSaFailed { source });
                            }
                        }
                    }
                    XfrmResidueClassification::Indeterminate => {
                        return Err(XfrmInstallRecoveryError::ClassificationIndeterminate {
                            object: XfrmInstallObject::Sa,
                        });
                    }
                }
            }

            Ok(())
        }
        .await;
        guard.finish(result.is_ok());
        result
    }
}

fn validate_classification(
    candidate_present: bool,
    classification: Option<XfrmResidueClassification>,
    object: XfrmInstallObject,
) -> Result<Option<XfrmResidueClassification>, XfrmInstallRecoveryError> {
    match (candidate_present, classification) {
        (true, None) => Err(XfrmInstallRecoveryError::MissingClassification { object }),
        (false, Some(_)) => Err(XfrmInstallRecoveryError::UnexpectedClassification { object }),
        (true, Some(XfrmResidueClassification::Indeterminate)) => {
            Err(XfrmInstallRecoveryError::ClassificationIndeterminate { object })
        }
        (_, classification) => Ok(classification),
    }
}

struct RunGuard {
    journal: XfrmInstallJournal,
    active: bool,
}

impl RunGuard {
    fn begin(journal: XfrmInstallJournal) -> Self {
        {
            let mut state = journal.state();
            // `XfrmStagedInstall::run` consumes the only staged value, so safe
            // Rust makes this the sole possible transition into `Running`.
            state.lifecycle = RunLifecycle::Running;
            state.touch();
        }
        Self {
            journal,
            active: true,
        }
    }

    fn finish(&mut self) {
        let mut state = self.journal.state();
        state.lifecycle = RunLifecycle::Finished;
        state.touch();
        self.active = false;
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.journal.state();
        if let Some(operation) = state.runner_inflight {
            state.mark_indeterminate(operation);
        }
        state.runner_supervision_lost = true;
        state.lifecycle = RunLifecycle::Finished;
        state.touch();
    }
}

struct RecoveryGuard {
    journal: XfrmInstallJournal,
    active: bool,
}

impl RecoveryGuard {
    fn new(journal: XfrmInstallJournal) -> Self {
        Self {
            journal,
            active: true,
        }
    }

    fn finish(&mut self, recovered: bool) {
        let mut state = self.journal.state();
        state.recovery_inflight = None;
        state.recovery_running = false;
        state.recovered = recovered;
        state.touch();
        self.active = false;
    }
}

impl Drop for RecoveryGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.journal.state();
        if let Some(operation) = state.recovery_inflight {
            state.mark_indeterminate(operation);
        }
        state.recovery_supervision_lost = true;
        state.recovery_running = false;
        state.touch();
    }
}

/// Affine cancellation-safe SA-plus-policy composite install.
pub struct XfrmStagedInstall {
    request: XfrmCompositeInstallRequest,
    journal: XfrmInstallJournal,
}

impl fmt::Debug for XfrmStagedInstall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmStagedInstall")
            .field("ownership", &self.journal.ownership())
            .finish_non_exhaustive()
    }
}

impl Drop for XfrmStagedInstall {
    fn drop(&mut self) {
        let mut state = self.journal.state();
        if state.lifecycle == RunLifecycle::NotStarted {
            state.lifecycle = RunLifecycle::Finished;
            state.touch();
        }
    }
}

impl XfrmStagedInstall {
    /// Stage a composite install without invoking the backend.
    #[must_use]
    pub fn new(request: XfrmCompositeInstallRequest) -> Self {
        let journal = XfrmInstallJournal::new(
            request.rollback_remove_sa(),
            request.rollback_remove_policy(),
        );
        Self { request, journal }
    }

    /// Clone the caller-visible mutation journal.
    pub fn journal(&self) -> XfrmInstallJournal {
        self.journal.clone()
    }

    /// Run and commit an exact outbound ESP SA plus allow-policy install, then
    /// return an opaque direction binding.
    ///
    /// This is the only fresh-install path that can mint
    /// [`InstalledOutboundSaBinding`]. It accepts only the namespace-bound
    /// production Linux actor, validates an unambiguous outbound allow policy
    /// before mutation, reuses the affine/cancellation-safe staged runner, and
    /// issues the binding only after both kernel ACKs, actor-local exact
    /// `GETPOLICY`/`GETSA` readback (including key comparison), and journal
    /// commit.
    /// Generic [`Self::run`] remains source-compatible but cannot mint this
    /// authority, regardless of which [`XfrmBackend`] it executes against.
    ///
    /// Clone [`Self::journal`] before starting if the caller needs to reconcile
    /// an observer cancellation. Cancellation can leave an acknowledged staged
    /// install for explicit recovery, but it never returns a binding or commits
    /// cleanup authority implicitly. Exact-readback failure likewise leaves the
    /// journal `Complete` and uncommitted so a caller-held clone retains cleanup
    /// authority; it never mints a binding from ACKs alone.
    pub async fn run_and_commit_outbound_sa_policy(
        self,
        backend: Arc<NamespaceBoundLinuxXfrmBackend>,
    ) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
        let expectation = validate_outbound_request(&self.request)?;
        let supplied_sa = self.request.sa.parameters.clone();
        let journal = self.journal();
        self.run(Arc::clone(&backend))
            .await
            .map_err(|source| OutboundSaBindingError::Install { source })?;
        backend
            .validate_current_outbound_sa_binding(expectation.clone(), supplied_sa)
            .await?;
        journal
            .commit()
            .map_err(|source| OutboundSaBindingError::Commit { source })?;
        journal.issue_outbound_binding(backend.as_ref(), expectation)
    }

    /// Consume and supervise this staged install exactly once.
    ///
    /// Dropping the returned future without polling performs no mutation and
    /// leaves no cleanup obligation. On its first poll, the future moves the
    /// operation into an owned Tokio worker. Dropping the observing future
    /// after that point detaches only the observer: the worker continues to
    /// drive the backend future and retains the live journal claim until the
    /// backend result is observed. This matters for adapters that internally
    /// use `spawn_blocking`, whose work continues after its `JoinHandle` is
    /// dropped. Recovery therefore cannot race a detached kernel mutation.
    ///
    /// The consuming receiver is the executable one-run invariant:
    ///
    /// ```compile_fail
    /// # use std::sync::Arc;
    /// # use opc_ipsec_xfrm::{XfrmBackend, XfrmStagedInstall};
    /// # fn staged() -> XfrmStagedInstall { unimplemented!() }
    /// # async fn cannot_run_twice<B: XfrmBackend + 'static>(backend: Arc<B>) {
    /// let install = staged();
    /// let first = install.run(backend.clone());
    /// let second = install.run(backend);
    /// # let _ = (first, second);
    /// # }
    /// ```
    pub async fn run<B>(
        self,
        backend: Arc<B>,
    ) -> Result<XfrmCompositeOutcome, XfrmStagedInstallRunError>
    where
        B: XfrmBackend + ?Sized + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| XfrmStagedInstallRunError::RuntimeUnavailable)?;
        let guard = RunGuard::begin(self.journal.clone());
        let worker = runtime.spawn(async move {
            let mut guard = guard;
            let result = self.run_inner(backend.as_ref()).await;
            guard.finish();
            result
        });
        match worker.await {
            Ok(result) => result.map_err(XfrmStagedInstallRunError::from),
            Err(_) => Err(XfrmStagedInstallRunError::WorkerTerminated),
        }
    }

    async fn run_inner<B>(
        &self,
        backend: &B,
    ) -> Result<XfrmCompositeOutcome, XfrmCompositeInstallError>
    where
        B: XfrmBackend + ?Sized,
    {
        {
            let mut state = self.journal.state();
            state.sa_possible = true;
            state.runner_inflight = Some(XfrmCompositeOperation::InstallSa);
            state.touch();
        }
        if let Err(source) = backend.install_sa(self.request.sa.clone()).await {
            let indeterminate = matches!(&source, XfrmError::StateIndeterminate { .. });
            let mut state = self.journal.state();
            state.runner_inflight = None;
            if indeterminate {
                state.mark_indeterminate(XfrmCompositeOperation::InstallSa);
            } else {
                state.clear_sa();
            }
            let outcome = if indeterminate {
                XfrmCompositeOutcome::indeterminate(XfrmCompositeOperation::InstallSa)
            } else {
                XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa)
            };
            return Err(XfrmCompositeInstallError::InstallSaFailed { source, outcome });
        }
        {
            let mut state = self.journal.state();
            state.runner_inflight = None;
            state.stage = Stage::SaAcquired;
            state.touch();
        }

        {
            let mut state = self.journal.state();
            state.policy_possible = true;
            state.runner_inflight = Some(XfrmCompositeOperation::InstallPolicy);
            state.touch();
        }
        if let Err(source) = backend.install_policy(self.request.policy.clone()).await {
            let policy_indeterminate = matches!(&source, XfrmError::StateIndeterminate { .. });
            {
                let mut state = self.journal.state();
                state.runner_inflight = None;
                if policy_indeterminate {
                    state.mark_indeterminate(XfrmCompositeOperation::InstallPolicy);
                } else {
                    state.clear_policy();
                }
                state.runner_inflight = Some(XfrmCompositeOperation::RollbackRemoveSa);
                state.touch();
            }

            let rollback = backend.remove_sa(self.request.rollback_remove_sa()).await;
            return match rollback {
                Ok(()) | Err(XfrmError::NotFound) => {
                    let mut state = self.journal.state();
                    state.runner_inflight = None;
                    state.clear_sa();
                    state.rolled_back = true;
                    let outcome = if policy_indeterminate {
                        rolled_back_with_possible_residue(XfrmCompositeOperation::InstallPolicy)
                    } else {
                        XfrmCompositeOutcome::rolled_back(XfrmCompositeOperation::InstallPolicy)
                    };
                    Err(XfrmCompositeInstallError::PolicyInstallRolledBack { source, outcome })
                }
                Err(rollback) => {
                    let mut state = self.journal.state();
                    state.runner_inflight = None;
                    if matches!(&rollback, XfrmError::StateIndeterminate { .. }) {
                        state.mark_indeterminate(XfrmCompositeOperation::RollbackRemoveSa);
                    } else {
                        state.touch();
                    }
                    Err(XfrmCompositeInstallError::PolicyInstallRollbackFailed {
                        source,
                        rollback,
                        outcome: XfrmCompositeOutcome::rollback_failed(
                            XfrmCompositeOperation::InstallPolicy,
                        ),
                    })
                }
            };
        }

        {
            let mut state = self.journal.state();
            state.runner_inflight = None;
            state.stage = Stage::Complete;
            state.touch();
        }
        Ok(XfrmCompositeOutcome::applied())
    }
}

fn rolled_back_with_possible_residue(
    failed_operation: XfrmCompositeOperation,
) -> XfrmCompositeOutcome {
    XfrmCompositeOutcome {
        applied: false,
        rolled_back: true,
        rollback_failed: false,
        partial_state_possible: true,
        failed_operation: Some(failed_operation),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Condvar, Mutex, MutexGuard};

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, IpAddress, PolicyParameters,
        QuerySaRequest, RekeyPolicyRequest, RekeySaRequest, SaParameters, SaState, SpiAllocation,
        XfrmAction, XfrmDirection, XfrmId, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
    };

    #[derive(Debug, Default)]
    struct BackendState {
        operations: Vec<&'static str>,
        sa_present: bool,
        policy_present: bool,
        removed_sa_requests: Vec<RemoveSaRequest>,
        removed_policy_requests: Vec<RemovePolicyRequest>,
    }

    #[derive(Debug)]
    struct GatedBackend {
        state: Mutex<BackendState>,
        install_sa_error: Option<XfrmError>,
        install_policy_error: Option<XfrmError>,
        remove_sa_error: Mutex<Option<XfrmError>>,
        remove_policy_error: Mutex<Option<XfrmError>>,
        pause_install_sa_result: bool,
        pause_install_policy_result: bool,
        pause_remove_sa_result: bool,
        pause_remove_policy_result: bool,
        install_sa_decided: Notify,
        install_policy_decided: Notify,
        remove_sa_decided: Notify,
        remove_policy_decided: Notify,
        install_sa_release: Notify,
        install_policy_release: Notify,
        remove_sa_release: Notify,
        remove_policy_release: Notify,
    }

    #[derive(Debug, Default)]
    struct SpawnBlockingState {
        started: bool,
        released: bool,
        sa_present: bool,
        policy_present: bool,
        remove_calls: usize,
    }

    #[derive(Debug, Default)]
    struct SpawnBlockingBackend {
        state: Arc<(Mutex<SpawnBlockingState>, Condvar)>,
    }

    #[derive(Debug, Default)]
    struct TerminatingBlockingState {
        install_started: bool,
        install_released: bool,
        remove_started: bool,
        remove_released: bool,
        sa_present: bool,
        policy_present: bool,
        remove_calls: usize,
    }

    #[derive(Debug)]
    struct TerminatingBlockingBackend {
        state: Arc<(Mutex<TerminatingBlockingState>, Condvar)>,
        panic_install_worker: bool,
        panic_remove_worker: bool,
    }

    impl TerminatingBlockingBackend {
        fn panics_during_install() -> Self {
            Self {
                state: Arc::default(),
                panic_install_worker: true,
                panic_remove_worker: false,
            }
        }

        fn panics_during_remove() -> Self {
            Self {
                state: Arc::default(),
                panic_install_worker: false,
                panic_remove_worker: true,
            }
        }

        fn lock(&self) -> MutexGuard<'_, TerminatingBlockingState> {
            self.state
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        async fn wait_for(&self, predicate: impl Fn(&TerminatingBlockingState) -> bool) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if predicate(&self.lock()) {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("detached blocking mutation starts");
        }

        async fn wait_until_install_started(&self) {
            self.wait_for(|state| state.install_started).await;
        }

        async fn wait_until_remove_started(&self) {
            self.wait_for(|state| state.remove_started).await;
        }

        async fn wait_until_sa_present(&self) {
            self.wait_for(|state| state.sa_present).await;
        }

        async fn wait_until_policy_absent(&self) {
            self.wait_for(|state| !state.policy_present).await;
        }

        fn release_install(&self) {
            self.lock().install_released = true;
            self.state.1.notify_all();
        }

        fn release_remove(&self) {
            self.lock().remove_released = true;
            self.state.1.notify_all();
        }

        fn remove_calls(&self) -> usize {
            self.lock().remove_calls
        }
    }

    impl SpawnBlockingBackend {
        fn lock(&self) -> MutexGuard<'_, SpawnBlockingState> {
            self.state
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        async fn wait_until_started(&self) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if self.lock().started {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("spawn_blocking mutation starts");
        }

        fn release(&self) {
            {
                self.lock().released = true;
            }
            self.state.1.notify_all();
        }

        fn remove_calls(&self) -> usize {
            self.lock().remove_calls
        }

        fn sa_present(&self) -> bool {
            self.lock().sa_present
        }
    }

    impl GatedBackend {
        fn new() -> Self {
            Self {
                state: Mutex::new(BackendState::default()),
                install_sa_error: None,
                install_policy_error: None,
                remove_sa_error: Mutex::new(None),
                remove_policy_error: Mutex::new(None),
                pause_install_sa_result: false,
                pause_install_policy_result: false,
                pause_remove_sa_result: false,
                pause_remove_policy_result: false,
                install_sa_decided: Notify::new(),
                install_policy_decided: Notify::new(),
                remove_sa_decided: Notify::new(),
                remove_policy_decided: Notify::new(),
                install_sa_release: Notify::new(),
                install_policy_release: Notify::new(),
                remove_sa_release: Notify::new(),
                remove_policy_release: Notify::new(),
            }
        }

        fn lock(&self) -> MutexGuard<'_, BackendState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn with_preexisting_sa_and_paused_result() -> Self {
            let backend = Self {
                pause_install_sa_result: true,
                ..Self::new()
            };
            backend.lock().sa_present = true;
            backend
        }

        fn with_preexisting_policy_and_paused_result() -> Self {
            let backend = Self {
                pause_install_policy_result: true,
                ..Self::new()
            };
            backend.lock().policy_present = true;
            backend
        }

        fn with_paused_sa_success() -> Self {
            Self {
                pause_install_sa_result: true,
                ..Self::new()
            }
        }

        fn with_paused_policy_success() -> Self {
            Self {
                pause_install_policy_result: true,
                ..Self::new()
            }
        }

        fn with_paused_policy_removal() -> Self {
            Self {
                pause_remove_policy_result: true,
                ..Self::new()
            }
        }

        fn with_paused_sa_removal() -> Self {
            Self {
                pause_remove_sa_result: true,
                ..Self::new()
            }
        }

        fn with_policy_error(error: XfrmError) -> Self {
            Self {
                install_policy_error: Some(error),
                ..Self::new()
            }
        }

        fn with_policy_and_rollback_errors(policy: XfrmError, rollback: XfrmError) -> Self {
            Self {
                install_policy_error: Some(policy),
                remove_sa_error: Mutex::new(Some(rollback)),
                ..Self::new()
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.lock().operations.clone()
        }

        fn sa_present(&self) -> bool {
            self.lock().sa_present
        }

        fn policy_present(&self) -> bool {
            self.lock().policy_present
        }

        fn set_policy_present(&self, present: bool) {
            self.lock().policy_present = present;
        }

        fn set_sa_present(&self, present: bool) {
            self.lock().sa_present = present;
        }

        fn removed_sa_requests(&self) -> Vec<RemoveSaRequest> {
            self.lock().removed_sa_requests.clone()
        }

        fn removed_policy_requests(&self) -> Vec<RemovePolicyRequest> {
            self.lock().removed_policy_requests.clone()
        }

        fn fail_remove_sa(&self, error: XfrmError) {
            *self
                .remove_sa_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }

        fn clear_remove_sa_error(&self) {
            *self
                .remove_sa_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }

        fn fail_remove_policy(&self, error: XfrmError) {
            *self
                .remove_policy_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }

        fn clear_remove_policy_error(&self) {
            *self
                .remove_policy_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }

        fn remove_sa_error(&self) -> Option<XfrmError> {
            self.remove_sa_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn remove_policy_error(&self) -> Option<XfrmError> {
            self.remove_policy_error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl XfrmBackend for GatedBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
            let result = {
                let mut state = self.lock();
                state.operations.push("install_sa");
                if let Some(error) = self.install_sa_error.clone() {
                    Err(error)
                } else if state.sa_present {
                    Err(XfrmError::AlreadyExists)
                } else {
                    state.sa_present = true;
                    Ok(())
                }
            };
            if self.pause_install_sa_result {
                self.install_sa_decided.notify_one();
                self.install_sa_release.notified().await;
            }
            result
        }

        async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
            let result = {
                let mut state = self.lock();
                state.operations.push("remove_sa");
                state.removed_sa_requests.push(request);
                if let Some(error) = self.remove_sa_error() {
                    Err(error)
                } else if state.sa_present {
                    state.sa_present = false;
                    Ok(())
                } else {
                    Err(XfrmError::NotFound)
                }
            };
            if self.pause_remove_sa_result {
                self.remove_sa_decided.notify_one();
                self.remove_sa_release.notified().await;
            }
            result
        }

        async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
            let result = {
                let mut state = self.lock();
                state.operations.push("install_policy");
                if let Some(error) = self.install_policy_error.clone() {
                    Err(error)
                } else if state.policy_present {
                    Err(XfrmError::AlreadyExists)
                } else {
                    state.policy_present = true;
                    Ok(())
                }
            };
            if self.pause_install_policy_result {
                self.install_policy_decided.notify_one();
                self.install_policy_release.notified().await;
            }
            result
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
            let result = {
                let mut state = self.lock();
                state.operations.push("remove_policy");
                state.removed_policy_requests.push(request);
                if let Some(error) = self.remove_policy_error() {
                    Err(error)
                } else if state.policy_present {
                    state.policy_present = false;
                    Ok(())
                } else {
                    Err(XfrmError::NotFound)
                }
            };
            if self.pause_remove_policy_result {
                self.remove_policy_decided.notify_one();
                self.remove_policy_release.notified().await;
            }
            result
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::mock())
        }
    }

    #[async_trait]
    impl XfrmBackend for SpawnBlockingBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
            let state = self.state.clone();
            let worker = tokio::task::spawn_blocking(move || {
                let (lock, changed) = &*state;
                let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                state.started = true;
                changed.notify_all();
                while !state.released {
                    state = changed
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                state.sa_present = true;
            });
            worker.await.map_err(|_| XfrmError::StateIndeterminate {
                operation: "test_spawn_blocking_install_sa",
            })
        }

        async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_sa(&self, _request: RemoveSaRequest) -> Result<(), XfrmError> {
            let mut state = self.lock();
            state.remove_calls += 1;
            if state.sa_present {
                state.sa_present = false;
                Ok(())
            } else {
                Err(XfrmError::NotFound)
            }
        }

        async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
            self.lock().policy_present = true;
            Ok(())
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
            let mut state = self.lock();
            state.remove_calls += 1;
            if state.policy_present {
                state.policy_present = false;
                Ok(())
            } else {
                Err(XfrmError::NotFound)
            }
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::mock())
        }
    }

    #[async_trait]
    impl XfrmBackend for TerminatingBlockingBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
            if self.panic_install_worker {
                let state = self.state.clone();
                let worker = tokio::task::spawn_blocking(move || {
                    let (lock, changed) = &*state;
                    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.install_started = true;
                    changed.notify_all();
                    while !state.install_released {
                        state = changed
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    state.sa_present = true;
                });
                self.wait_until_install_started().await;
                drop(worker);
                panic!("test-only supervised install worker failure");
            }
            self.lock().sa_present = true;
            Ok(())
        }

        async fn query_sa(&self, _request: QuerySaRequest) -> Result<SaState, XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_sa(&self, _request: RemoveSaRequest) -> Result<(), XfrmError> {
            self.lock().remove_calls += 1;
            let mut state = self.lock();
            if state.sa_present {
                state.sa_present = false;
                Ok(())
            } else {
                Err(XfrmError::NotFound)
            }
        }

        async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
            self.lock().policy_present = true;
            Ok(())
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
            self.lock().remove_calls += 1;
            if self.panic_remove_worker {
                let state = self.state.clone();
                let worker = tokio::task::spawn_blocking(move || {
                    let (lock, changed) = &*state;
                    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.remove_started = true;
                    changed.notify_all();
                    while !state.remove_released {
                        state = changed
                            .wait(state)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    state.policy_present = false;
                });
                self.wait_until_remove_started().await;
                drop(worker);
                panic!("test-only supervised recovery worker failure");
            }
            let mut state = self.lock();
            if state.policy_present {
                state.policy_present = false;
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
        XfrmSelector::new(ipv4(10, 77, 88, 99), ipv4(203, 0, 113, 9), 50)
    }

    fn sa_parameters() -> SaParameters {
        SaParameters {
            selector: selector(),
            id: XfrmId {
                destination: ipv4(203, 0, 113, 9),
                spi: 0xdead_beef,
                protocol: 50,
            },
            source_address: ipv4(10, 77, 88, 99),
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
                source_address: ipv4(10, 77, 88, 99),
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

    fn classify(
        plan: &XfrmInstallRecoveryPlan,
        policy: Option<XfrmResidueClassification>,
        sa: Option<XfrmResidueClassification>,
    ) -> XfrmInstallRecoveryClassification {
        let mut classification = plan.classification();
        if let Some(policy) = policy {
            classification = classification.with_policy(policy);
        }
        if let Some(sa) = sa {
            classification = classification.with_sa(sa);
        }
        classification
    }

    fn classify_all_owned(plan: &XfrmInstallRecoveryPlan) -> XfrmInstallRecoveryClassification {
        classify(
            plan,
            plan.policy().map(|_| XfrmResidueClassification::Owned),
            plan.sa().map(|_| XfrmResidueClassification::Owned),
        )
    }

    fn composite_error(error: XfrmStagedInstallRunError) -> XfrmCompositeInstallError {
        match error {
            XfrmStagedInstallRunError::Composite { source } => source,
            other => panic!("unexpected staged runner error: {other}"),
        }
    }

    async fn wait_for_ownership(journal: &XfrmInstallJournal, expected: XfrmInstallOwnership) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if journal.ownership() == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervised worker reaches expected ownership");
    }

    #[tokio::test]
    async fn successful_install_commits_across_every_journal_clone() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let second = journal.clone();

        let outcome = staged.run(backend.clone()).await.expect("install applies");
        assert_eq!(outcome, XfrmCompositeOutcome::applied());
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Complete);
        journal.commit().expect("complete install commits");
        journal.commit().expect("commit retry is idempotent");

        assert_eq!(journal.ownership(), XfrmInstallOwnership::Committed);
        assert_eq!(second.ownership(), XfrmInstallOwnership::Committed);
        assert!(second.recovery_plan().is_empty());
        let error = second
            .recover(backend.clone(), second.recovery_plan().classification())
            .await
            .expect_err("committed authority cannot recover");
        assert!(matches!(error, XfrmInstallRecoveryError::Committed));
        assert_eq!(backend.operations(), vec!["install_sa", "install_policy"]);
    }

    #[tokio::test]
    async fn dropping_unpolled_runner_finishes_without_cleanup_obligation() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner = staged.run(backend.clone());

        let error = journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect_err("unpolled runner has not finished");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        drop(runner);

        assert_eq!(journal.ownership(), XfrmInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());
        let plan = journal.recovery_plan();
        let unexpected = plan
            .classification()
            .with_sa(XfrmResidueClassification::Owned);
        let error = journal
            .recover(backend.clone(), unexpected)
            .await
            .expect_err("classification for absent candidate fails closed");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::UnexpectedClassification {
                object: XfrmInstallObject::Sa
            }
        ));
        journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect("empty recovery retires the journal");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn dropping_staged_value_before_run_finishes_empty_journal() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        drop(staged);

        assert_eq!(journal.ownership(), XfrmInstallOwnership::NotStarted);
        let plan = journal.recovery_plan();
        assert!(plan.is_empty());
        journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect("dropped unstarted operation has no cleanup obligation");
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Recovered);
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn pending_sa_already_exists_never_authorizes_deleting_preexisting_sa() {
        let backend = Arc::new(GatedBackend::with_preexisting_sa_and_paused_result());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner_backend = backend.clone();
        let runner = tokio::spawn(staged.run(runner_backend));
        backend.install_sa_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("detached observer does not cancel supervised install");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));

        backend.install_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::NotStarted).await;

        assert!(backend.sa_present());
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.removed_sa_requests().is_empty());
        assert_eq!(backend.operations(), vec!["install_sa"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_observer_cannot_race_a_live_spawn_blocking_mutation() {
        let backend = Arc::new(SpawnBlockingBackend::default());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let observer = tokio::spawn(staged.run(backend.clone()));
        backend.wait_until_started().await;

        observer.abort();
        assert!(observer.await.is_err());
        assert_eq!(journal.ownership(), XfrmInstallOwnership::SaInFlight);

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("recovery cannot overtake detached blocking work");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        assert_eq!(backend.remove_calls(), 0);

        backend.release();
        wait_for_ownership(&journal, XfrmInstallOwnership::Complete).await;
        assert!(backend.sa_present());

        let completed_plan = journal.recovery_plan();
        journal
            .recover(backend.clone(), classify_all_owned(&completed_plan))
            .await
            .expect("completed blocking mutation is safely recoverable");
        assert!(!backend.sa_present());
        assert_eq!(backend.remove_calls(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_install_worker_permanently_blocks_in_process_recovery() {
        let backend = Arc::new(TerminatingBlockingBackend::panics_during_install());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();

        let error = staged
            .run(backend.clone())
            .await
            .expect_err("supervised worker panic is typed");
        assert!(matches!(error, XfrmStagedInstallRunError::WorkerTerminated));
        assert!(matches!(
            journal.ownership(),
            XfrmInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::InstallSa)
            }
        ));

        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("detached blocking install permanently poisons recovery");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 0);

        backend.release_install();
        backend.wait_until_sa_present().await;

        let plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("later quiescence cannot forge supervised completion");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_recovery_worker_permanently_blocks_overlapping_removal() {
        let backend = Arc::new(TerminatingBlockingBackend::panics_during_remove());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged
            .run(backend.clone())
            .await
            .expect("install completes before recovery");

        let plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("supervised recovery panic is typed");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert!(matches!(
            journal.ownership(),
            XfrmInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::RemovePolicy)
            }
        ));

        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("a second recovery cannot overlap detached removal");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 1);

        backend.release_remove();
        backend.wait_until_policy_absent().await;

        let plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("unobserved removal completion cannot restore authority");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_shutdown_during_blocking_install_permanently_blocks_recovery() {
        let backend = Arc::new(SpawnBlockingBackend::default());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runtime_backend = backend.clone();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("test runtime builds");
            runtime.block_on(async move {
                let observer = tokio::spawn(staged.run(runtime_backend.clone()));
                runtime_backend.wait_until_started().await;
                drop(observer);
            });
            runtime.shutdown_timeout(std::time::Duration::from_millis(25));
        })
        .join()
        .expect("runtime shutdown thread joins");

        assert!(matches!(
            journal.ownership(),
            XfrmInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::InstallSa)
            }
        ));
        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("runtime shutdown cannot expose premature recovery authority");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 0);

        backend.release();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !backend.sa_present() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached blocking mutation eventually completes");

        let plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("post-shutdown quiescence remains untrusted");
        assert!(matches!(error, XfrmInstallRecoveryError::WorkerTerminated));
        assert_eq!(backend.remove_calls(), 0);
    }

    #[tokio::test]
    async fn pending_policy_already_exists_removes_only_acknowledged_sa() {
        let backend = Arc::new(GatedBackend::with_preexisting_policy_and_paused_result());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner_backend = backend.clone();
        let runner = tokio::spawn(staged.run(runner_backend));
        backend.install_policy_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("supervised policy result remains live");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));

        backend.install_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::RolledBack).await;

        assert!(!backend.sa_present());
        assert!(backend.policy_present());
        assert!(backend.removed_policy_requests().is_empty());
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
    }

    #[tokio::test]
    async fn cancellation_after_applied_sa_requires_owned_classification() {
        let backend = Arc::new(GatedBackend::with_paused_sa_success());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner_backend = backend.clone();
        let runner = tokio::spawn(staged.run(runner_backend));
        backend.install_sa_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());
        assert!(backend.sa_present());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("supervised SA result remains live");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));

        backend.install_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::Complete).await;
        let plan = journal.recovery_plan();
        journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect("completed supervised install is recoverable");
        assert!(!backend.sa_present());
    }

    #[tokio::test]
    async fn cancellation_after_applied_policy_recovers_policy_before_sa() {
        let backend = Arc::new(GatedBackend::with_paused_policy_success());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner_backend = backend.clone();
        let runner = tokio::spawn(staged.run(runner_backend));
        backend.install_policy_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("supervised policy result remains live");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));

        backend.install_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::Complete).await;
        let plan = journal.recovery_plan();
        journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect("classified complete residue recovers");
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_policy", "remove_sa"]
        );
    }

    #[tokio::test]
    async fn recovery_is_rejected_while_runner_is_live() {
        let backend = Arc::new(GatedBackend::with_paused_policy_success());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let runner_backend = backend.clone();
        let runner = tokio::spawn(staged.run(runner_backend));
        backend.install_policy_decided.notified().await;

        let plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect_err("live runner excludes recovery");
        assert!(matches!(error, XfrmInstallRecoveryError::RunnerNotFinished));
        backend.install_policy_release.notify_one();
        runner
            .await
            .expect("observer joins")
            .expect("supervised install completes");
    }

    #[tokio::test]
    async fn concurrent_recovery_is_rejected_without_a_second_backend_call() {
        let backend = Arc::new(GatedBackend::with_paused_policy_removal());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        let first_classification = classify_all_owned(&plan);
        let first_journal = journal.clone();
        let first_backend = backend.clone();
        let first = tokio::spawn(first_journal.recover(first_backend, first_classification));
        backend.remove_policy_decided.notified().await;

        let current = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&current))
            .await
            .expect_err("recovery claim is exclusive");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::RecoveryInProgress
        ));
        assert_eq!(backend.removed_policy_requests().len(), 1);
        assert_eq!(
            journal.commit(),
            Err(XfrmInstallCommitError::RecoveryInProgress)
        );

        backend.remove_policy_release.notify_one();
        first
            .await
            .expect("first recovery joins")
            .expect("first recovery succeeds");
    }

    #[tokio::test]
    async fn dropped_policy_recovery_observer_cannot_race_a_replacement() {
        let backend = Arc::new(GatedBackend::with_paused_policy_removal());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let old_plan = journal.recovery_plan();
        let recovery_journal = journal.clone();
        let recovery_backend = backend.clone();
        let classification = classify_all_owned(&old_plan);
        let recovery = tokio::spawn(recovery_journal.recover(recovery_backend, classification));
        backend.remove_policy_decided.notified().await;
        recovery.abort();
        assert!(recovery.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("supervised removal retains the recovery claim");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::RecoveryInProgress
        ));

        backend.remove_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::Recovered).await;
        backend.set_policy_present(true);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal recovery retry is a no-op");

        assert!(backend.policy_present());
        assert_eq!(backend.removed_policy_requests().len(), 1);
        assert!(!backend.sa_present());
    }

    #[tokio::test]
    async fn dropped_sa_recovery_observer_cannot_race_a_replacement() {
        let backend = Arc::new(GatedBackend::with_paused_sa_removal());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let old_plan = journal.recovery_plan();
        let recovery_journal = journal.clone();
        let recovery_backend = backend.clone();
        let classification = classify_all_owned(&old_plan);
        let recovery = tokio::spawn(recovery_journal.recover(recovery_backend, classification));
        backend.remove_sa_decided.notified().await;
        recovery.abort();
        assert!(recovery.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(backend.clone(), classify_all_owned(&live_plan))
            .await
            .expect_err("supervised removal retains the recovery claim");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::RecoveryInProgress
        ));

        backend.remove_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmInstallOwnership::Recovered).await;
        backend.set_sa_present(true);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal recovery retry is a no-op");
        assert!(backend.sa_present());
        assert_eq!(backend.removed_sa_requests().len(), 1);
    }

    #[tokio::test]
    async fn indeterminate_recovery_error_rotates_plan_and_preserves_operation() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        backend.fail_remove_policy(XfrmError::StateIndeterminate {
            operation: "test_remove_policy",
        });

        let old_plan = journal.recovery_plan();
        let stale = classify_all_owned(&old_plan);
        let error = journal
            .recover(backend.clone(), classify_all_owned(&old_plan))
            .await
            .expect_err("indeterminate removal is reported");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::RemovePolicyFailed {
                source: XfrmError::StateIndeterminate { .. }
            }
        ));
        let current = journal.recovery_plan();
        assert!(current
            .indeterminate_operations()
            .contains(XfrmCompositeOperation::RemovePolicy));
        let error = journal
            .recover(backend.clone(), stale)
            .await
            .expect_err("classification predating indeterminate result is stale");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::StaleClassification
        ));

        backend.clear_remove_policy_error();
        let classification = classify(
            &current,
            Some(XfrmResidueClassification::Absent),
            Some(XfrmResidueClassification::Owned),
        );
        journal
            .recover(backend.clone(), classification)
            .await
            .expect("fresh classification completes recovery");
    }

    #[tokio::test]
    async fn observed_already_exists_sa_never_enters_recovery_plan() {
        let backend = Arc::new(GatedBackend::new());
        backend.lock().sa_present = true;
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("pre-existing SA rejects install"),
        );

        assert!(matches!(
            error,
            XfrmCompositeInstallError::InstallSaFailed {
                source: XfrmError::AlreadyExists,
                ..
            }
        ));
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.removed_sa_requests().is_empty());
    }

    #[tokio::test]
    async fn indeterminate_sa_install_requires_classified_recovery() {
        let backend = Arc::new(GatedBackend {
            install_sa_error: Some(XfrmError::StateIndeterminate {
                operation: "test_install_sa",
            }),
            ..GatedBackend::new()
        });
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("SA result is indeterminate"),
        );

        assert!(matches!(
            error,
            XfrmCompositeInstallError::InstallSaFailed {
                source: XfrmError::StateIndeterminate { .. },
                ..
            }
        ));
        assert!(error.outcome().partial_state_possible);
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert!(plan.policy().is_none());
        assert_eq!(plan.sa(), Some(&expected_remove_sa()));
        assert!(plan
            .indeterminate_operations()
            .contains(XfrmCompositeOperation::InstallSa));

        let classification = classify(&plan, None, Some(XfrmResidueClassification::Absent));
        journal
            .recover(backend.clone(), classification)
            .await
            .expect("classified absence safely retires the candidate");
    }

    #[tokio::test]
    async fn observed_already_exists_policy_rolls_back_only_new_sa() {
        let backend = Arc::new(GatedBackend::new());
        backend.lock().policy_present = true;
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("pre-existing policy rejects install"),
        );

        assert!(matches!(
            error,
            XfrmCompositeInstallError::PolicyInstallRolledBack {
                source: XfrmError::AlreadyExists,
                ..
            }
        ));
        assert_eq!(journal.ownership(), XfrmInstallOwnership::RolledBack);
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.policy_present());
        assert!(backend.removed_policy_requests().is_empty());
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
    }

    #[tokio::test]
    async fn fully_rolled_back_policy_failure_has_no_residual_authority() {
        let backend = Arc::new(GatedBackend::with_policy_error(XfrmError::Unavailable));
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("policy failure rolls its SA back"),
        );

        assert!(matches!(
            error,
            XfrmCompositeInstallError::PolicyInstallRolledBack { .. }
        ));
        assert!(error.outcome().rolled_back);
        assert!(!error.outcome().partial_state_possible);
        assert_eq!(journal.ownership(), XfrmInstallOwnership::RolledBack);
        assert!(journal.recovery_plan().is_empty());
    }

    #[tokio::test]
    async fn rollback_failure_retains_exact_sa_candidate() {
        let backend = Arc::new(GatedBackend::with_policy_error(XfrmError::Unavailable));
        backend.fail_remove_sa(XfrmError::Unavailable);
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("rollback failure is typed"),
        );

        assert!(matches!(
            error,
            XfrmCompositeInstallError::PolicyInstallRollbackFailed { .. }
        ));
        assert!(error.outcome().partial_state_possible);
        assert_eq!(journal.ownership(), XfrmInstallOwnership::SaAcquired);
        backend.clear_remove_sa_error();
        let plan = journal.recovery_plan();
        journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect("retry removes exact SA");
        assert!(!backend.sa_present());
    }

    #[tokio::test]
    async fn indeterminate_rollback_is_explicit_and_requires_readback() {
        let backend = Arc::new(GatedBackend::with_policy_and_rollback_errors(
            XfrmError::Unavailable,
            XfrmError::StateIndeterminate {
                operation: "test_rollback",
            },
        ));
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("rollback is indeterminate"),
        );

        assert!(error.outcome().partial_state_possible);
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert!(plan
            .indeterminate_operations()
            .contains(XfrmCompositeOperation::RollbackRemoveSa));
    }

    #[tokio::test]
    async fn policy_and_rollback_uncertainty_are_both_preserved() {
        let backend = Arc::new(GatedBackend::with_policy_and_rollback_errors(
            XfrmError::StateIndeterminate {
                operation: "test_policy",
            },
            XfrmError::StateIndeterminate {
                operation: "test_rollback",
            },
        ));
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("both operations are indeterminate"),
        );

        assert!(error.outcome().partial_state_possible);
        let operations = journal.recovery_plan().indeterminate_operations();
        assert!(operations.contains(XfrmCompositeOperation::InstallPolicy));
        assert!(operations.contains(XfrmCompositeOperation::RollbackRemoveSa));
        assert_eq!(operations.iter().count(), 2);
    }

    #[tokio::test]
    async fn indeterminate_policy_with_successful_sa_rollback_reports_partial_state() {
        let backend = Arc::new(GatedBackend::with_policy_error(
            XfrmError::StateIndeterminate {
                operation: "test_policy",
            },
        ));
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        let error = composite_error(
            staged
                .run(backend.clone())
                .await
                .expect_err("policy result is indeterminate"),
        );

        assert!(error.outcome().rolled_back);
        assert!(error.outcome().partial_state_possible);
        assert!(journal.ownership().has_residue());
        assert_eq!(
            journal.recovery_plan().policy(),
            Some(&expected_remove_policy())
        );
        assert_eq!(journal.recovery_plan().sa(), None);
    }

    #[tokio::test]
    async fn classifications_fail_closed_before_backend_mutation() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        let before = backend.operations();

        let plan = journal.recovery_plan();
        let missing = classify(&plan, Some(XfrmResidueClassification::Owned), None);
        let error = journal
            .recover(backend.clone(), missing)
            .await
            .expect_err("missing SA classification fails closed");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::MissingClassification {
                object: XfrmInstallObject::Sa
            }
        ));

        let indeterminate = classify(
            &plan,
            Some(XfrmResidueClassification::Indeterminate),
            Some(XfrmResidueClassification::Owned),
        );
        let error = journal
            .recover(backend.clone(), indeterminate)
            .await
            .expect_err("indeterminate classification fails closed");
        assert!(matches!(
            error,
            XfrmInstallRecoveryError::ClassificationIndeterminate {
                object: XfrmInstallObject::Policy
            }
        ));
        assert_eq!(backend.operations(), before);
    }

    #[tokio::test]
    async fn not_found_recovery_is_idempotent_and_retry_is_a_noop() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedInstall::new(install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        backend.lock().policy_present = false;
        backend.lock().sa_present = false;
        let plan = journal.recovery_plan();
        journal
            .recover(backend.clone(), classify_all_owned(&plan))
            .await
            .expect("NotFound clears exact candidates");
        let count = backend.operations().len();
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal retry is a no-op");
        assert_eq!(backend.operations().len(), count);
    }

    #[test]
    fn debug_surfaces_redact_keys_addresses_and_spis() {
        let mut request = install_request();
        request.sa.parameters.auth = Some((
            crate::AuthAlgorithm::hmac_sha256(96),
            crate::KeyMaterial::new(vec![0xab; 32]),
        ));
        let staged = XfrmStagedInstall::new(request);
        let journal = staged.journal();
        let plan = journal.recovery_plan();
        let classification = plan.classification();

        for surface in [
            format!("{staged:?}"),
            format!("{journal:?}"),
            format!("{plan:?}"),
            format!("{classification:?}"),
        ] {
            assert!(
                !surface.contains("10, 77, 88, 99"),
                "address leak: {surface}"
            );
            assert!(
                !surface.contains("203, 0, 113, 9"),
                "address leak: {surface}"
            );
            assert!(!surface.contains("3735928559"), "SPI leak: {surface}");
            assert!(!surface.contains("deadbeef"), "SPI leak: {surface}");
            assert!(!surface.contains("171"), "key leak: {surface}");
            assert!(!surface.contains("0xab"), "key leak: {surface}");
        }
    }
}
