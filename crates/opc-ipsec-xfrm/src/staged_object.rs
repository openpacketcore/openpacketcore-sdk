//! Cancellation-safe staged single-object XFRM installation.
//!
//! [`XfrmStagedObjectInstall`] is the single-object counterpart of
//! [`crate::XfrmStagedInstall`]: it supervises one exact SA-only or
//! policy-only install without inventing a dummy companion mutation. This
//! covers consumers that install an SA which intentionally reuses an existing
//! shared policy, or that install an additional policy direction for one SA.
//! Calling [`XfrmBackend::install_sa`] or [`XfrmBackend::install_policy`]
//! directly inside a cancellable future preserves the issued-but-unobserved
//! ownership ambiguity the staged boundary exists to close.
//!
//! The staged value is affine: calling [`XfrmStagedObjectInstall::run`]
//! consumes it, so safe Rust cannot start the same mutation twice. A caller
//! clones [`XfrmObjectInstallJournal`] before starting the runner. On first
//! poll, the runner moves into an owned Tokio worker; dropping its observing
//! future cannot cancel an adapter's detached `spawn_blocking` mutation or
//! make recovery race that mutation. The journal records the acknowledged
//! mutation and an unobserved backend result, and remains available if the
//! observer is dropped.
//!
//! Destructive recovery is deliberately explicit. A caller obtains the
//! current [`XfrmObjectInstallRecoveryPlan`], classifies the exact candidate
//! as [`XfrmResidueClassification::Owned`], `Absent`, `Foreign`, or
//! `Indeterminate`, and passes the generation-bound classification to
//! [`XfrmObjectInstallJournal::recover`]. Recovery is supervised by the same
//! rule: dropping its observer leaves the owned worker and recovery claim
//! live until the issued removal returns. An unobserved result never becomes
//! blind deletion authority. If either owned worker terminates abnormally,
//! the journal records supervision loss and permanently disables in-process
//! recovery: a detached blocking syscall may still complete after the async
//! worker is gone. A fresh process must re-establish namespace-wide exclusion
//! and authoritative state before deciding how to handle residue.
//! Classification must be performed while the caller holds the product's
//! namespace-wide XFRM writer exclusion; exact readback alone cannot
//! distinguish an identical foreign replacement.

use std::{
    error::Error,
    fmt,
    future::Future,
    sync::{Arc, Mutex},
};

use crate::{
    InstallPolicyRequest, InstallSaRequest, RemovePolicyRequest, RemoveSaRequest, XfrmBackend,
    XfrmCompositeOperation, XfrmError, XfrmInstallObject, XfrmResidueClassification,
};

/// Typed single-object XFRM install request.
///
/// `Debug` reports only the object label; exact identities are available to
/// privileged recovery code by matching the variants.
#[allow(clippy::large_enum_variant)] // one-shot request moved once into the staged value
#[derive(Clone, PartialEq, Eq)]
pub enum XfrmObjectInstallRequest {
    /// Install one exact Security Association.
    Sa(InstallSaRequest),
    /// Install one exact Security Policy.
    Policy(InstallPolicyRequest),
}

impl XfrmObjectInstallRequest {
    /// Object kind installed by this request.
    pub const fn object(&self) -> XfrmInstallObject {
        match self {
            Self::Sa(_) => XfrmInstallObject::Sa,
            Self::Policy(_) => XfrmInstallObject::Policy,
        }
    }

    const fn install_operation(&self) -> XfrmCompositeOperation {
        match self {
            Self::Sa(_) => XfrmCompositeOperation::InstallSa,
            Self::Policy(_) => XfrmCompositeOperation::InstallPolicy,
        }
    }

    const fn remove_operation(&self) -> XfrmCompositeOperation {
        match self {
            Self::Sa(_) => XfrmCompositeOperation::RemoveSa,
            Self::Policy(_) => XfrmCompositeOperation::RemovePolicy,
        }
    }

    /// Exact removal identity of the object this request installs.
    ///
    /// The derivation matches the composite rollback requests: the SA removal
    /// selects the exact destination/protocol/SPI plus lookup mark, and the
    /// policy removal selects the exact selector/direction plus lookup mark.
    fn removal(&self) -> XfrmObjectRemovalRequest {
        match self {
            Self::Sa(request) => {
                let parameters = &request.parameters;
                XfrmObjectRemovalRequest::Sa(RemoveSaRequest {
                    destination: parameters.id.destination,
                    protocol: parameters.id.protocol,
                    spi: parameters.id.spi,
                    mark: parameters.mark,
                })
            }
            Self::Policy(request) => {
                let parameters = &request.parameters;
                XfrmObjectRemovalRequest::Policy(RemovePolicyRequest {
                    selector: parameters.selector.clone(),
                    direction: parameters.direction,
                    mark: parameters.mark,
                })
            }
        }
    }
}

impl fmt::Debug for XfrmObjectInstallRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmObjectInstallRequest")
            .field("object", &self.object().as_str())
            .finish_non_exhaustive()
    }
}

/// Exact removal identity retained for staged single-object residue.
///
/// `Debug` reports only the object label; privileged recovery code matches
/// the variants to obtain the exact removal request for classified readback.
#[derive(Clone, PartialEq, Eq)]
pub enum XfrmObjectRemovalRequest {
    /// Remove one exact Security Association.
    Sa(RemoveSaRequest),
    /// Remove one exact Security Policy.
    Policy(RemovePolicyRequest),
}

impl XfrmObjectRemovalRequest {
    /// Object kind removed by this request.
    pub const fn object(&self) -> XfrmInstallObject {
        match self {
            Self::Sa(_) => XfrmInstallObject::Sa,
            Self::Policy(_) => XfrmInstallObject::Policy,
        }
    }
}

impl fmt::Debug for XfrmObjectRemovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmObjectRemovalRequest")
            .field("object", &self.object().as_str())
            .finish_non_exhaustive()
    }
}

/// Typed mutation ownership of a staged single-object install.
///
/// Variants carry only stable labels. The exact identity remains available
/// from [`XfrmObjectInstallRecoveryPlan`] and is omitted from its `Debug`
/// output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmObjectInstallOwnership {
    /// The runner has not acquired or issued a mutation, or every issued
    /// mutation was observed as rejected.
    NotStarted,
    /// The install is currently in flight.
    InstallInFlight,
    /// The install was acknowledged and residue may remain.
    Acquired,
    /// Classified recovery is currently issuing this removal.
    Recovering {
        /// Removal operation in flight.
        operation: XfrmCompositeOperation,
    },
    /// Recovery retired the candidate by exact removal or classification.
    Recovered,
    /// The caller committed the acknowledged install and retired the journal's
    /// cleanup authority. Product teardown now owns the installed state.
    Committed,
    /// A backend result was not observed.
    Indeterminate {
        /// Operation whose final state was not observed.
        operation: XfrmCompositeOperation,
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

impl XfrmObjectInstallOwnership {
    /// Stable machine-readable ownership label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::InstallInFlight => "install_in_flight",
            Self::Acquired => "acquired",
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
            Self::InstallInFlight
                | Self::Acquired
                | Self::Recovering { .. }
                | Self::Indeterminate { .. }
                | Self::SupervisionLost { .. }
        )
    }
}

/// Generation-bound classification for an exact single-object recovery plan.
///
/// Construct this value with
/// [`XfrmObjectInstallRecoveryPlan::classification`]. A classification becomes
/// stale whenever runner or recovery state changes.
#[derive(Clone)]
pub struct XfrmObjectInstallRecoveryClassification {
    generation: Arc<()>,
    classification: Option<XfrmResidueClassification>,
}

impl XfrmObjectInstallRecoveryClassification {
    /// Classify the exact candidate in the originating plan.
    #[must_use]
    pub fn with_candidate(mut self, classification: XfrmResidueClassification) -> Self {
        self.classification = Some(classification);
        self
    }
}

impl fmt::Debug for XfrmObjectInstallRecoveryClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmObjectInstallRecoveryClassification")
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

/// Exact removal candidate retained for staged single-object residue.
///
/// `Debug` reports only candidate presence and operation labels; use
/// [`Self::candidate`] when privileged recovery code needs the exact identity.
#[derive(Clone)]
pub struct XfrmObjectInstallRecoveryPlan {
    candidate: Option<XfrmObjectRemovalRequest>,
    indeterminate: Option<XfrmCompositeOperation>,
    supervision_lost: bool,
    generation: Arc<()>,
}

impl XfrmObjectInstallRecoveryPlan {
    /// True when no candidate remains.
    pub const fn is_empty(&self) -> bool {
        self.candidate.is_none()
    }

    /// Exact removal candidate, when one remains.
    pub const fn candidate(&self) -> Option<&XfrmObjectRemovalRequest> {
        self.candidate.as_ref()
    }

    /// Operation whose final result was not observed, when any.
    pub const fn indeterminate_operation(&self) -> Option<XfrmCompositeOperation> {
        self.indeterminate
    }

    /// True when an owned async worker terminated abnormally and in-process
    /// recovery is permanently disabled for this journal.
    pub const fn supervision_lost(&self) -> bool {
        self.supervision_lost
    }

    /// True when exact readback and writer-fence classification is required
    /// because a backend result was not observed.
    pub const fn requires_readback(&self) -> bool {
        self.supervision_lost || self.indeterminate.is_some()
    }

    /// True when recovery requires a classification value.
    pub const fn requires_classification(&self) -> bool {
        !self.is_empty()
    }

    /// Start a generation-bound classification for this exact plan.
    #[must_use]
    pub fn classification(&self) -> XfrmObjectInstallRecoveryClassification {
        XfrmObjectInstallRecoveryClassification {
            generation: self.generation.clone(),
            classification: None,
        }
    }
}

impl fmt::Debug for XfrmObjectInstallRecoveryPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmObjectInstallRecoveryPlan")
            .field("candidate_present", &self.candidate.is_some())
            .field("indeterminate_operation", &self.indeterminate)
            .field("supervision_lost", &self.supervision_lost)
            .finish_non_exhaustive()
    }
}

impl PartialEq for XfrmObjectInstallRecoveryPlan {
    fn eq(&self, other: &Self) -> bool {
        self.candidate == other.candidate
            && self.indeterminate == other.indeterminate
            && self.supervision_lost == other.supervision_lost
            && Arc::ptr_eq(&self.generation, &other.generation)
    }
}

impl Eq for XfrmObjectInstallRecoveryPlan {}

/// Error returned by [`XfrmObjectInstallJournal::commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmObjectInstallCommitError {
    /// The runner was never started or remains live.
    RunnerNotFinished,
    /// Classified recovery is currently live.
    RecoveryInProgress,
    /// The install was not acknowledged or retained as residue.
    NotAcquired,
    /// An unobserved backend result must be classified before ownership
    /// transfer.
    Indeterminate,
    /// Recovery already retired the journal's candidate.
    AlreadyRecovered,
}

impl XfrmObjectInstallCommitError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunnerNotFinished => "xfrm_object_install_commit_runner_not_finished",
            Self::RecoveryInProgress => "xfrm_object_install_commit_recovery_in_progress",
            Self::NotAcquired => "xfrm_object_install_commit_not_acquired",
            Self::Indeterminate => "xfrm_object_install_commit_indeterminate",
            Self::AlreadyRecovered => "xfrm_object_install_commit_already_recovered",
        }
    }
}

impl fmt::Display for XfrmObjectInstallCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmObjectInstallCommitError {}

/// Error returned by the supervised [`XfrmStagedObjectInstall::run`] worker.
#[derive(Debug, Clone)]
pub enum XfrmStagedObjectInstallRunError {
    /// The backend rejected or could not prove the install. The journal
    /// retains residue only when the source is
    /// [`XfrmError::StateIndeterminate`]; an observed rejection such as
    /// [`XfrmError::AlreadyExists`] authorizes no removal of the pre-existing
    /// object.
    InstallFailed {
        /// Install operation that failed.
        operation: XfrmCompositeOperation,
        /// Redaction-safe backend error.
        source: XfrmError,
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

impl XfrmStagedObjectInstallRunError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InstallFailed { .. } => "xfrm_staged_object_install_failed",
            Self::RuntimeUnavailable => "xfrm_staged_object_install_runtime_unavailable",
            Self::WorkerTerminated => "xfrm_staged_object_install_worker_terminated",
        }
    }

    /// True when the backend result is indeterminate and the journal retains
    /// the exact candidate for classified recovery.
    pub fn is_indeterminate(&self) -> bool {
        matches!(
            self,
            Self::InstallFailed {
                source: XfrmError::StateIndeterminate { .. },
                ..
            } | Self::WorkerTerminated
        )
    }
}

impl fmt::Display for XfrmStagedObjectInstallRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmStagedObjectInstallRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InstallFailed { source, .. } => Some(source),
            Self::RuntimeUnavailable | Self::WorkerTerminated => None,
        }
    }
}

/// Error returned by [`XfrmObjectInstallJournal::recover`].
#[derive(Debug, Clone)]
pub enum XfrmObjectInstallRecoveryError {
    /// The exact removal failed.
    RemoveFailed {
        /// Removal operation that failed.
        operation: XfrmCompositeOperation,
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
    /// The retained candidate had no classification.
    MissingClassification {
        /// Candidate lacking classification.
        object: XfrmInstallObject,
    },
    /// A classification was supplied for a candidate absent from the plan.
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

impl XfrmObjectInstallRecoveryError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RemoveFailed { .. } => "xfrm_object_install_recovery_remove_failed",
            Self::RunnerNotFinished => "xfrm_object_install_recovery_runner_not_finished",
            Self::RecoveryInProgress => "xfrm_object_install_recovery_in_progress",
            Self::RuntimeUnavailable => "xfrm_object_install_recovery_runtime_unavailable",
            Self::WorkerTerminated => "xfrm_object_install_recovery_worker_terminated",
            Self::Committed => "xfrm_object_install_recovery_committed",
            Self::StaleClassification => "xfrm_object_install_recovery_stale_classification",
            Self::MissingClassification { .. } => {
                "xfrm_object_install_recovery_missing_classification"
            }
            Self::UnexpectedClassification { .. } => {
                "xfrm_object_install_recovery_unexpected_classification"
            }
            Self::ClassificationIndeterminate { .. } => {
                "xfrm_object_install_recovery_classification_indeterminate"
            }
        }
    }
}

impl fmt::Display for XfrmObjectInstallRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmObjectInstallRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RemoveFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    NotStarted,
    Acquired,
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
    possible: bool,
    recovered: bool,
    committed: bool,
    uncertainty: Option<XfrmCompositeOperation>,
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
            possible: false,
            recovered: false,
            committed: false,
            uncertainty: None,
            generation: Arc::new(()),
        }
    }

    fn touch(&mut self) {
        self.generation = Arc::new(());
    }

    fn mark_indeterminate(&mut self, operation: XfrmCompositeOperation) {
        self.uncertainty = Some(operation);
        self.touch();
    }

    fn clear(&mut self) {
        self.possible = false;
        self.uncertainty = None;
        self.touch();
    }

    fn ownership(&self) -> XfrmObjectInstallOwnership {
        if self.committed {
            return XfrmObjectInstallOwnership::Committed;
        }
        if self.recovered {
            return XfrmObjectInstallOwnership::Recovered;
        }
        if self.recovery_supervision_lost {
            return XfrmObjectInstallOwnership::SupervisionLost {
                operation: self.recovery_inflight,
            };
        }
        if self.runner_supervision_lost {
            return XfrmObjectInstallOwnership::SupervisionLost {
                operation: self.runner_inflight,
            };
        }
        if let Some(operation) = self.recovery_inflight {
            return XfrmObjectInstallOwnership::Recovering { operation };
        }
        if let Some(operation) = self.uncertainty {
            return XfrmObjectInstallOwnership::Indeterminate { operation };
        }
        if self.runner_inflight.is_some() {
            return XfrmObjectInstallOwnership::InstallInFlight;
        }
        if self.possible {
            XfrmObjectInstallOwnership::Acquired
        } else {
            XfrmObjectInstallOwnership::NotStarted
        }
    }

    fn plan(&self, inner: &JournalInner) -> XfrmObjectInstallRecoveryPlan {
        let terminal = self.committed || self.recovered;
        XfrmObjectInstallRecoveryPlan {
            candidate: (!terminal && self.possible).then(|| inner.removal.clone()),
            indeterminate: if terminal { None } else { self.uncertainty },
            supervision_lost: !terminal
                && (self.runner_supervision_lost || self.recovery_supervision_lost),
            generation: self.generation.clone(),
        }
    }
}

struct JournalInner {
    object: XfrmInstallObject,
    install_operation: XfrmCompositeOperation,
    remove_operation: XfrmCompositeOperation,
    removal: XfrmObjectRemovalRequest,
    state: Mutex<JournalState>,
}

/// Caller-visible staged single-object mutation journal.
#[derive(Clone)]
pub struct XfrmObjectInstallJournal {
    inner: Arc<JournalInner>,
}

impl fmt::Debug for XfrmObjectInstallJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        let plan = state.plan(&self.inner);
        f.debug_struct("XfrmObjectInstallJournal")
            .field("object", &self.inner.object.as_str())
            .field("ownership", &state.ownership())
            .field("recovery_plan", &plan)
            .finish()
    }
}

impl XfrmObjectInstallJournal {
    fn new(
        object: XfrmInstallObject,
        install_operation: XfrmCompositeOperation,
        remove_operation: XfrmCompositeOperation,
        removal: XfrmObjectRemovalRequest,
    ) -> Self {
        Self {
            inner: Arc::new(JournalInner {
                object,
                install_operation,
                remove_operation,
                removal,
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

    /// Object kind supervised by this journal.
    pub fn object(&self) -> XfrmInstallObject {
        self.inner.object
    }

    /// Current typed mutation ownership.
    pub fn ownership(&self) -> XfrmObjectInstallOwnership {
        self.state().ownership()
    }

    /// Current exact, generation-bound recovery plan.
    pub fn recovery_plan(&self) -> XfrmObjectInstallRecoveryPlan {
        self.state().plan(&self.inner)
    }

    /// Commit an acknowledged install to product ownership.
    ///
    /// Every journal clone observes the resulting
    /// [`XfrmObjectInstallOwnership::Committed`] state, and no clone can
    /// subsequently invoke journal recovery. Product teardown must use its
    /// own authoritative installed-object record after this transfer.
    pub fn commit(&self) -> Result<(), XfrmObjectInstallCommitError> {
        let mut state = self.state();
        if state.committed {
            return Ok(());
        }
        if state.lifecycle != RunLifecycle::Finished {
            return Err(XfrmObjectInstallCommitError::RunnerNotFinished);
        }
        if state.runner_supervision_lost || state.recovery_supervision_lost {
            return Err(XfrmObjectInstallCommitError::Indeterminate);
        }
        if state.recovery_running {
            return Err(XfrmObjectInstallCommitError::RecoveryInProgress);
        }
        if state.recovered {
            return Err(XfrmObjectInstallCommitError::AlreadyRecovered);
        }
        if state.uncertainty.is_some() {
            return Err(XfrmObjectInstallCommitError::Indeterminate);
        }
        if state.stage != Stage::Acquired || !state.possible {
            return Err(XfrmObjectInstallCommitError::NotAcquired);
        }
        state.committed = true;
        state.touch();
        Ok(())
    }

    /// Apply a generation-bound, exact recovery classification.
    ///
    /// A retained candidate must be classified. `Owned` issues the exact
    /// retained removal, `Absent` and `Foreign` retire the candidate without
    /// mutation, and `Indeterminate` fails closed. Classification is evidence
    /// supplied by the product while holding namespace-wide writer exclusion;
    /// callers must not infer `Owned` merely from install intent or matching
    /// readback.
    ///
    /// Only one recovery worker can run at a time. Once the returned future
    /// is polled, dropping it detaches only the observer; its owned worker
    /// keeps the recovery claim until the issued backend removal returns. If
    /// the worker itself terminates while a removal may be in flight, the
    /// journal records permanent supervision loss and rejects every later
    /// in-process recovery attempt.
    pub fn recover<B>(
        &self,
        backend: Arc<B>,
        classification: XfrmObjectInstallRecoveryClassification,
    ) -> impl Future<Output = Result<(), XfrmObjectInstallRecoveryError>> + Send + 'static
    where
        B: XfrmBackend + ?Sized + 'static,
    {
        let journal = self.clone();
        async move {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|_| XfrmObjectInstallRecoveryError::RuntimeUnavailable)?;
            let worker = runtime.spawn(async move {
                journal
                    .recover_inner(backend.as_ref(), classification)
                    .await
            });
            match worker.await {
                Ok(result) => result,
                Err(_) => Err(XfrmObjectInstallRecoveryError::WorkerTerminated),
            }
        }
    }

    async fn recover_inner<B>(
        &self,
        backend: &B,
        classification: XfrmObjectInstallRecoveryClassification,
    ) -> Result<(), XfrmObjectInstallRecoveryError>
    where
        B: XfrmBackend + ?Sized,
    {
        let (plan, candidate_classification) = {
            let mut state = self.state();
            if state.runner_supervision_lost || state.recovery_supervision_lost {
                return Err(XfrmObjectInstallRecoveryError::WorkerTerminated);
            }
            if state.lifecycle != RunLifecycle::Finished {
                return Err(XfrmObjectInstallRecoveryError::RunnerNotFinished);
            }
            if state.committed {
                return Err(XfrmObjectInstallRecoveryError::Committed);
            }
            if state.recovered {
                return Ok(());
            }
            if state.recovery_running {
                return Err(XfrmObjectInstallRecoveryError::RecoveryInProgress);
            }
            if !Arc::ptr_eq(&classification.generation, &state.generation) {
                return Err(XfrmObjectInstallRecoveryError::StaleClassification);
            }
            let plan = state.plan(&self.inner);
            let candidate_classification =
                match (plan.candidate.is_some(), classification.classification) {
                    (true, None) => {
                        return Err(XfrmObjectInstallRecoveryError::MissingClassification {
                            object: self.inner.object,
                        });
                    }
                    (false, Some(_)) => {
                        return Err(XfrmObjectInstallRecoveryError::UnexpectedClassification {
                            object: self.inner.object,
                        });
                    }
                    (true, Some(XfrmResidueClassification::Indeterminate)) => {
                        return Err(
                            XfrmObjectInstallRecoveryError::ClassificationIndeterminate {
                                object: self.inner.object,
                            },
                        );
                    }
                    (_, classification) => classification,
                };
            state.recovery_running = true;
            state.touch();
            (plan, candidate_classification)
        };

        let mut guard = RecoveryGuard::new(self.clone());
        let result = async {
            if let (Some(request), Some(classification)) =
                (plan.candidate, candidate_classification)
            {
                match classification {
                    XfrmResidueClassification::Absent | XfrmResidueClassification::Foreign => {
                        self.state().clear();
                    }
                    XfrmResidueClassification::Owned => {
                        let remove_operation = self.inner.remove_operation;
                        {
                            let mut state = self.state();
                            state.uncertainty = None;
                            state.recovery_inflight = Some(remove_operation);
                            state.touch();
                        }
                        let removal = match request {
                            XfrmObjectRemovalRequest::Sa(request) => {
                                backend.remove_sa(request).await
                            }
                            XfrmObjectRemovalRequest::Policy(request) => {
                                backend.remove_policy(request).await
                            }
                        };
                        match removal {
                            Ok(()) | Err(XfrmError::NotFound) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                state.clear();
                            }
                            Err(source) => {
                                let mut state = self.state();
                                state.recovery_inflight = None;
                                if matches!(&source, XfrmError::StateIndeterminate { .. }) {
                                    state.mark_indeterminate(remove_operation);
                                } else {
                                    state.touch();
                                }
                                return Err(XfrmObjectInstallRecoveryError::RemoveFailed {
                                    operation: remove_operation,
                                    source,
                                });
                            }
                        }
                    }
                    XfrmResidueClassification::Indeterminate => {
                        return Err(
                            XfrmObjectInstallRecoveryError::ClassificationIndeterminate {
                                object: self.inner.object,
                            },
                        );
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

struct RunGuard {
    journal: XfrmObjectInstallJournal,
    active: bool,
}

impl RunGuard {
    fn begin(journal: XfrmObjectInstallJournal) -> Self {
        {
            let mut state = journal.state();
            // `XfrmStagedObjectInstall::run` consumes the only staged value,
            // so safe Rust makes this the sole possible transition into
            // `Running`.
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
    journal: XfrmObjectInstallJournal,
    active: bool,
}

impl RecoveryGuard {
    fn new(journal: XfrmObjectInstallJournal) -> Self {
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

/// Affine cancellation-safe single-object install.
pub struct XfrmStagedObjectInstall {
    request: XfrmObjectInstallRequest,
    journal: XfrmObjectInstallJournal,
}

impl fmt::Debug for XfrmStagedObjectInstall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XfrmStagedObjectInstall")
            .field("object", &self.request.object().as_str())
            .field("ownership", &self.journal.ownership())
            .finish_non_exhaustive()
    }
}

impl Drop for XfrmStagedObjectInstall {
    fn drop(&mut self) {
        let mut state = self.journal.state();
        if state.lifecycle == RunLifecycle::NotStarted {
            state.lifecycle = RunLifecycle::Finished;
            state.touch();
        }
    }
}

impl XfrmStagedObjectInstall {
    /// Stage a single-object install without invoking the backend.
    #[must_use]
    pub fn new(request: XfrmObjectInstallRequest) -> Self {
        let journal = XfrmObjectInstallJournal::new(
            request.object(),
            request.install_operation(),
            request.remove_operation(),
            request.removal(),
        );
        Self { request, journal }
    }

    /// Clone the caller-visible mutation journal.
    pub fn journal(&self) -> XfrmObjectInstallJournal {
        self.journal.clone()
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
    /// # use opc_ipsec_xfrm::{XfrmBackend, XfrmStagedObjectInstall};
    /// # fn staged() -> XfrmStagedObjectInstall { unimplemented!() }
    /// # async fn cannot_run_twice<B: XfrmBackend + 'static>(backend: Arc<B>) {
    /// let install = staged();
    /// let first = install.run(backend.clone());
    /// let second = install.run(backend);
    /// # let _ = (first, second);
    /// # }
    /// ```
    pub async fn run<B>(self, backend: Arc<B>) -> Result<(), XfrmStagedObjectInstallRunError>
    where
        B: XfrmBackend + ?Sized + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| XfrmStagedObjectInstallRunError::RuntimeUnavailable)?;
        let install_operation = self.journal.inner.install_operation;
        let guard = RunGuard::begin(self.journal.clone());
        let worker = runtime.spawn(async move {
            let mut guard = guard;
            let result = self.run_inner(backend.as_ref()).await;
            guard.finish();
            result
        });
        match worker.await {
            Ok(result) => result.map_err(|source| XfrmStagedObjectInstallRunError::InstallFailed {
                operation: install_operation,
                source,
            }),
            Err(_) => Err(XfrmStagedObjectInstallRunError::WorkerTerminated),
        }
    }

    async fn run_inner<B>(&self, backend: &B) -> Result<(), XfrmError>
    where
        B: XfrmBackend + ?Sized,
    {
        let install_operation = self.journal.inner.install_operation;
        {
            let mut state = self.journal.state();
            state.possible = true;
            state.runner_inflight = Some(install_operation);
            state.touch();
        }
        let result = match &self.request {
            XfrmObjectInstallRequest::Sa(request) => backend.install_sa(request.clone()).await,
            XfrmObjectInstallRequest::Policy(request) => {
                backend.install_policy(request.clone()).await
            }
        };
        if let Err(source) = result {
            let indeterminate = matches!(&source, XfrmError::StateIndeterminate { .. });
            let mut state = self.journal.state();
            state.runner_inflight = None;
            if indeterminate {
                state.mark_indeterminate(install_operation);
            } else {
                state.clear();
            }
            return Err(source);
        }
        {
            let mut state = self.journal.state();
            state.runner_inflight = None;
            state.stage = Stage::Acquired;
            state.touch();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Condvar, Mutex, MutexGuard};

    use async_trait::async_trait;
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        AllocateSpiRequest, IpAddress, PolicyParameters, QuerySaRequest, RekeyPolicyRequest,
        RekeySaRequest, SaParameters, SaState, SpiAllocation, XfrmAction, XfrmDirection, XfrmId,
        XfrmMark, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
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

        fn with_paused_sa_removal() -> Self {
            Self {
                pause_remove_sa_result: true,
                ..Self::new()
            }
        }

        fn with_paused_policy_removal() -> Self {
            Self {
                pause_remove_policy_result: true,
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

        fn set_sa_present(&self, present: bool) {
            self.lock().sa_present = present;
        }

        fn set_policy_present(&self, present: bool) {
            self.lock().policy_present = present;
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

    #[derive(Debug, Default)]
    struct SpawnBlockingState {
        started: bool,
        released: bool,
        sa_present: bool,
        remove_calls: usize,
    }

    #[derive(Debug, Default)]
    struct SpawnBlockingBackend {
        state: Arc<(Mutex<SpawnBlockingState>, Condvar)>,
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
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            Err(XfrmError::UnsupportedFeature { feature: "test" })
        }

        async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
            let mut state = self.lock();
            state.remove_calls += 1;
            Ok(())
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::mock())
        }
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

    fn sa_install_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: sa_parameters(),
        })
    }

    fn policy_install_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
            parameters: policy_parameters(),
        })
    }

    fn expected_remove_sa() -> RemoveSaRequest {
        RemoveSaRequest {
            destination: ipv4(203, 0, 113, 9),
            protocol: 50,
            spi: 0xdead_beef,
            mark: None,
        }
    }

    fn expected_remove_policy() -> RemovePolicyRequest {
        RemovePolicyRequest {
            selector: selector(),
            direction: XfrmDirection::Out,
            mark: None,
        }
    }

    fn classify(
        plan: &XfrmObjectInstallRecoveryPlan,
        classification: XfrmResidueClassification,
    ) -> XfrmObjectInstallRecoveryClassification {
        plan.classification().with_candidate(classification)
    }

    fn install_failure(
        error: XfrmStagedObjectInstallRunError,
    ) -> (XfrmCompositeOperation, XfrmError) {
        match error {
            XfrmStagedObjectInstallRunError::InstallFailed { operation, source } => {
                (operation, source)
            }
            other => panic!("unexpected staged runner error: {other}"),
        }
    }

    async fn wait_for_ownership(
        journal: &XfrmObjectInstallJournal,
        expected: XfrmObjectInstallOwnership,
    ) {
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
    async fn successful_sa_install_commits_across_every_journal_clone() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let second = journal.clone();

        staged.run(backend.clone()).await.expect("install applies");
        assert_eq!(journal.object(), XfrmInstallObject::Sa);
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Acquired);
        assert!(journal.ownership().has_residue());
        assert_eq!(
            journal.recovery_plan().candidate(),
            Some(&XfrmObjectRemovalRequest::Sa(expected_remove_sa()))
        );

        journal.commit().expect("acknowledged install commits");
        journal.commit().expect("commit retry is idempotent");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Committed);
        assert_eq!(second.ownership(), XfrmObjectInstallOwnership::Committed);
        assert!(second.recovery_plan().is_empty());
        let error = second
            .recover(backend.clone(), second.recovery_plan().classification())
            .await
            .expect_err("committed authority cannot recover");
        assert!(matches!(error, XfrmObjectInstallRecoveryError::Committed));
        assert_eq!(backend.operations(), vec!["install_sa"]);
    }

    #[tokio::test]
    async fn successful_policy_install_commits_across_every_journal_clone() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let second = journal.clone();

        staged.run(backend.clone()).await.expect("install applies");
        assert_eq!(journal.object(), XfrmInstallObject::Policy);
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Acquired);
        assert_eq!(
            journal.recovery_plan().candidate(),
            Some(&XfrmObjectRemovalRequest::Policy(expected_remove_policy()))
        );

        journal.commit().expect("acknowledged install commits");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Committed);
        assert_eq!(second.ownership(), XfrmObjectInstallOwnership::Committed);
        assert!(second.recovery_plan().is_empty());
        let error = second
            .recover(backend.clone(), second.recovery_plan().classification())
            .await
            .expect_err("committed authority cannot recover");
        assert!(matches!(error, XfrmObjectInstallRecoveryError::Committed));
        assert_eq!(backend.operations(), vec!["install_policy"]);
    }

    #[tokio::test]
    async fn dropping_unpolled_sa_runner_and_staged_value_performs_no_mutation() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let runner = staged.run(backend.clone());

        let error = journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect_err("unpolled runner has not finished");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));
        drop(runner);

        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        assert!(!journal.ownership().has_residue());
        assert!(journal.recovery_plan().is_empty());
        let plan = journal.recovery_plan();
        let unexpected = plan
            .classification()
            .with_candidate(XfrmResidueClassification::Owned);
        let error = journal
            .recover(backend.clone(), unexpected)
            .await
            .expect_err("classification for absent candidate fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::UnexpectedClassification {
                object: XfrmInstallObject::Sa
            }
        ));
        journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect("empty recovery retires the journal");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);

        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        drop(staged);
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("dropped unstarted operation has no cleanup obligation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn dropping_unpolled_policy_runner_and_staged_value_performs_no_mutation() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let runner = staged.run(backend.clone());

        let error = journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect_err("unpolled runner has not finished");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));
        drop(runner);

        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());
        let plan = journal.recovery_plan();
        let unexpected = plan
            .classification()
            .with_candidate(XfrmResidueClassification::Owned);
        let error = journal
            .recover(backend.clone(), unexpected)
            .await
            .expect_err("classification for absent candidate fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::UnexpectedClassification {
                object: XfrmInstallObject::Policy
            }
        ));
        journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect("empty recovery retires the journal");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);

        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        drop(staged);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("dropped unstarted operation has no cleanup obligation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn dropped_sa_observer_keeps_worker_and_claim_live_until_result() {
        let backend = Arc::new(GatedBackend::with_paused_sa_success());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let runner = tokio::spawn(staged.run(backend.clone()));
        backend.install_sa_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::InstallInFlight
        );
        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("detached observer does not cancel supervised install");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::RunnerNotFinished)
        );

        backend.install_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::Acquired).await;
        assert!(backend.sa_present());
        assert_eq!(backend.operations(), vec!["install_sa"]);

        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("completed supervised install is recoverable");
        assert!(!backend.sa_present());
    }

    #[tokio::test]
    async fn dropped_policy_observer_keeps_worker_and_claim_live_until_result() {
        let backend = Arc::new(GatedBackend::with_paused_policy_success());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let runner = tokio::spawn(staged.run(backend.clone()));
        backend.install_policy_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::InstallInFlight
        );
        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("detached observer does not cancel supervised install");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));

        backend.install_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::Acquired).await;
        assert!(backend.policy_present());
        assert_eq!(backend.operations(), vec!["install_policy"]);

        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("completed supervised install is recoverable");
        assert!(!backend.policy_present());
    }

    #[tokio::test]
    async fn pending_sa_already_exists_never_authorizes_removal_of_preexisting_sa() {
        let backend = Arc::new(GatedBackend::with_preexisting_sa_and_paused_result());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let runner = tokio::spawn(staged.run(backend.clone()));
        backend.install_sa_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("detached observer does not cancel supervised install");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));

        backend.install_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::NotStarted).await;

        assert!(backend.sa_present());
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.removed_sa_requests().is_empty());
        assert_eq!(backend.operations(), vec!["install_sa"]);
    }

    #[tokio::test]
    async fn pending_policy_already_exists_never_authorizes_removal_of_preexisting_policy() {
        let backend = Arc::new(GatedBackend::with_preexisting_policy_and_paused_result());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let runner = tokio::spawn(staged.run(backend.clone()));
        backend.install_policy_decided.notified().await;
        runner.abort();
        assert!(runner.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("detached observer does not cancel supervised install");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RunnerNotFinished
        ));

        backend.install_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::NotStarted).await;

        assert!(backend.policy_present());
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.removed_policy_requests().is_empty());
        assert_eq!(backend.operations(), vec!["install_policy"]);
    }

    #[tokio::test]
    async fn observed_already_exists_never_enters_recovery_plan() {
        let backend = Arc::new(GatedBackend::new());
        backend.lock().sa_present = true;
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let (operation, source) = install_failure(
            staged
                .run(backend.clone())
                .await
                .expect_err("pre-existing SA rejects install"),
        );
        assert_eq!(operation, XfrmCompositeOperation::InstallSa);
        assert!(matches!(source, XfrmError::AlreadyExists));
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.sa_present());
        assert!(backend.removed_sa_requests().is_empty());

        let backend = Arc::new(GatedBackend::new());
        backend.lock().policy_present = true;
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let (operation, source) = install_failure(
            staged
                .run(backend.clone())
                .await
                .expect_err("pre-existing policy rejects install"),
        );
        assert_eq!(operation, XfrmCompositeOperation::InstallPolicy);
        assert!(matches!(source, XfrmError::AlreadyExists));
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.policy_present());
        assert!(backend.removed_policy_requests().is_empty());
    }

    #[tokio::test]
    async fn indeterminate_sa_install_requires_explicit_classified_readback() {
        let backend = Arc::new(GatedBackend {
            install_sa_error: Some(XfrmError::StateIndeterminate {
                operation: "test_install_sa",
            }),
            ..GatedBackend::new()
        });
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        let error = staged
            .run(backend.clone())
            .await
            .expect_err("SA result is indeterminate");
        assert!(error.is_indeterminate());
        let (operation, source) = install_failure(error);
        assert_eq!(operation, XfrmCompositeOperation::InstallSa);
        assert!(matches!(source, XfrmError::StateIndeterminate { .. }));

        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::Indeterminate {
                operation: XfrmCompositeOperation::InstallSa
            }
        );
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert!(plan.requires_classification());
        assert_eq!(
            plan.indeterminate_operation(),
            Some(XfrmCompositeOperation::InstallSa)
        );
        assert_eq!(
            plan.candidate(),
            Some(&XfrmObjectRemovalRequest::Sa(expected_remove_sa()))
        );
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );

        let error = journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect_err("unclassified candidate fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::MissingClassification {
                object: XfrmInstallObject::Sa
            }
        ));
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Indeterminate),
            )
            .await
            .expect_err("indeterminate classification fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::ClassificationIndeterminate {
                object: XfrmInstallObject::Sa
            }
        ));
        assert!(backend.removed_sa_requests().is_empty());

        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Absent),
            )
            .await
            .expect("classified absence safely retires the candidate");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.removed_sa_requests().is_empty());
    }

    #[tokio::test]
    async fn indeterminate_policy_install_requires_explicit_classified_readback() {
        let backend = Arc::new(GatedBackend {
            install_policy_error: Some(XfrmError::StateIndeterminate {
                operation: "test_install_policy",
            }),
            ..GatedBackend::new()
        });
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        let error = staged
            .run(backend.clone())
            .await
            .expect_err("policy result is indeterminate");
        assert!(error.is_indeterminate());
        let (operation, source) = install_failure(error);
        assert_eq!(operation, XfrmCompositeOperation::InstallPolicy);
        assert!(matches!(source, XfrmError::StateIndeterminate { .. }));

        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::Indeterminate {
                operation: XfrmCompositeOperation::InstallPolicy
            }
        );
        let plan = journal.recovery_plan();
        assert!(plan.requires_readback());
        assert!(plan.requires_classification());
        assert_eq!(
            plan.indeterminate_operation(),
            Some(XfrmCompositeOperation::InstallPolicy)
        );
        assert_eq!(
            plan.candidate(),
            Some(&XfrmObjectRemovalRequest::Policy(expected_remove_policy()))
        );
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );

        let error = journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect_err("unclassified candidate fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::MissingClassification {
                object: XfrmInstallObject::Policy
            }
        ));
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Indeterminate),
            )
            .await
            .expect_err("indeterminate classification fails closed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::ClassificationIndeterminate {
                object: XfrmInstallObject::Policy
            }
        ));

        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Foreign),
            )
            .await
            .expect("classified foreign object safely retires the candidate");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.removed_policy_requests().is_empty());
    }

    #[tokio::test]
    async fn recovery_removes_only_the_exact_owned_sa() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("owned classification removes the exact SA");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(!backend.sa_present());
        assert_eq!(backend.removed_sa_requests(), vec![expected_remove_sa()]);
        assert_eq!(backend.operations(), vec!["install_sa", "remove_sa"]);
    }

    #[tokio::test]
    async fn recovery_removes_only_the_exact_owned_policy() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("owned classification removes the exact policy");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(!backend.policy_present());
        assert_eq!(
            backend.removed_policy_requests(),
            vec![expected_remove_policy()]
        );
        assert_eq!(
            backend.operations(),
            vec!["install_policy", "remove_policy"]
        );
    }

    #[tokio::test]
    async fn absent_and_foreign_sa_classifications_never_delete() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Absent),
            )
            .await
            .expect("absent classification retires without mutation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.sa_present());
        assert!(backend.removed_sa_requests().is_empty());

        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Foreign),
            )
            .await
            .expect("foreign classification retires without mutation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.sa_present());
        assert!(backend.removed_sa_requests().is_empty());
        assert_eq!(backend.operations(), vec!["install_sa"]);
    }

    #[tokio::test]
    async fn absent_and_foreign_policy_classifications_never_delete() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Absent),
            )
            .await
            .expect("absent classification retires without mutation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.policy_present());
        assert!(backend.removed_policy_requests().is_empty());

        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Foreign),
            )
            .await
            .expect("foreign classification retires without mutation");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert!(backend.policy_present());
        assert!(backend.removed_policy_requests().is_empty());
        assert_eq!(backend.operations(), vec!["install_policy"]);
    }

    #[tokio::test]
    async fn dropped_sa_recovery_observer_keeps_claim_while_removal_is_live() {
        let backend = Arc::new(GatedBackend::with_paused_sa_removal());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        let recovery_journal = journal.clone();
        let recovery_backend = backend.clone();
        let classification = classify(&plan, XfrmResidueClassification::Owned);
        let recovery = tokio::spawn(recovery_journal.recover(recovery_backend, classification));
        backend.remove_sa_decided.notified().await;
        recovery.abort();
        assert!(recovery.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("supervised removal retains the recovery claim");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RecoveryInProgress
        ));
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::RecoveryInProgress)
        );

        backend.remove_sa_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::Recovered).await;
        backend.set_sa_present(true);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal recovery retry is a no-op");
        assert!(backend.sa_present());
        assert_eq!(backend.removed_sa_requests().len(), 1);
    }

    #[tokio::test]
    async fn dropped_policy_recovery_observer_keeps_claim_while_removal_is_live() {
        let backend = Arc::new(GatedBackend::with_paused_policy_removal());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        let recovery_journal = journal.clone();
        let recovery_backend = backend.clone();
        let classification = classify(&plan, XfrmResidueClassification::Owned);
        let recovery = tokio::spawn(recovery_journal.recover(recovery_backend, classification));
        backend.remove_policy_decided.notified().await;
        recovery.abort();
        assert!(recovery.await.is_err());

        let live_plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&live_plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("supervised removal retains the recovery claim");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RecoveryInProgress
        ));

        backend.remove_policy_release.notify_one();
        wait_for_ownership(&journal, XfrmObjectInstallOwnership::Recovered).await;
        backend.set_policy_present(true);
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal recovery retry is a no-op");
        assert!(backend.policy_present());
        assert_eq!(backend.removed_policy_requests().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_recovery_is_rejected_without_a_second_backend_call() {
        let backend = Arc::new(GatedBackend::with_paused_policy_removal());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        let first_journal = journal.clone();
        let first_backend = backend.clone();
        let classification = classify(&plan, XfrmResidueClassification::Owned);
        let first = tokio::spawn(first_journal.recover(first_backend, classification));
        backend.remove_policy_decided.notified().await;

        let current = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&current, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("recovery claim is exclusive");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RecoveryInProgress
        ));
        assert_eq!(backend.removed_policy_requests().len(), 1);
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::RecoveryInProgress)
        );

        backend.remove_policy_release.notify_one();
        first
            .await
            .expect("first recovery joins")
            .expect("first recovery succeeds");
    }

    #[tokio::test]
    async fn indeterminate_removal_rotates_plan_and_requires_fresh_classification() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");
        backend.fail_remove_sa(XfrmError::StateIndeterminate {
            operation: "test_remove_sa",
        });

        let old_plan = journal.recovery_plan();
        let stale = classify(&old_plan, XfrmResidueClassification::Owned);
        let error = journal
            .recover(backend.clone(), stale.clone())
            .await
            .expect_err("indeterminate removal is reported");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RemoveFailed {
                operation: XfrmCompositeOperation::RemoveSa,
                source: XfrmError::StateIndeterminate { .. }
            }
        ));
        let current = journal.recovery_plan();
        assert!(current.requires_readback());
        assert_eq!(
            current.indeterminate_operation(),
            Some(XfrmCompositeOperation::RemoveSa)
        );
        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::Indeterminate {
                operation: XfrmCompositeOperation::RemoveSa
            }
        );
        let error = journal
            .recover(backend.clone(), stale)
            .await
            .expect_err("classification predating indeterminate result is stale");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::StaleClassification
        ));

        backend.clear_remove_sa_error();
        journal
            .recover(
                backend.clone(),
                classify(&current, XfrmResidueClassification::Absent),
            )
            .await
            .expect("fresh classification completes recovery");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert_eq!(backend.removed_sa_requests().len(), 1);
    }

    #[tokio::test]
    async fn not_found_recovery_is_idempotent_and_retry_is_a_noop() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        backend.lock().policy_present = false;
        let plan = journal.recovery_plan();
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("NotFound clears the exact candidate");
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        let count = backend.operations().len();
        journal
            .recover(backend.clone(), journal.recovery_plan().classification())
            .await
            .expect("terminal retry is a no-op");
        assert_eq!(backend.operations().len(), count);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_install_worker_permanently_blocks_commit_and_recovery() {
        let backend = Arc::new(TerminatingBlockingBackend::panics_during_install());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();

        let error = staged
            .run(backend.clone())
            .await
            .expect_err("supervised worker panic is typed");
        assert!(matches!(
            error,
            XfrmStagedObjectInstallRunError::WorkerTerminated
        ));
        assert!(error.is_indeterminate());
        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::InstallSa)
            }
        );
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );

        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("detached blocking install permanently poisons recovery");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(backend.remove_calls(), 0);

        backend.release_install();
        backend.wait_until_sa_present().await;

        let plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("later quiescence cannot forge supervised completion");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );
        assert_eq!(backend.remove_calls(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_recovery_worker_permanently_blocks_overlapping_removal() {
        let backend = Arc::new(TerminatingBlockingBackend::panics_during_remove());
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        staged
            .run(backend.clone())
            .await
            .expect("install completes before recovery");

        let plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("supervised recovery panic is typed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::RemovePolicy)
            }
        );

        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("a second recovery cannot overlap detached removal");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );
        assert_eq!(backend.remove_calls(), 1);

        backend.release_remove();
        backend.wait_until_policy_absent().await;

        let plan = journal.recovery_plan();
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("unobserved removal completion cannot restore authority");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(backend.remove_calls(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_shutdown_during_blocking_install_permanently_blocks_recovery() {
        let backend = Arc::new(SpawnBlockingBackend::default());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
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

        assert_eq!(
            journal.ownership(),
            XfrmObjectInstallOwnership::SupervisionLost {
                operation: Some(XfrmCompositeOperation::InstallSa)
            }
        );
        assert_eq!(
            journal.commit(),
            Err(XfrmObjectInstallCommitError::Indeterminate)
        );
        let plan = journal.recovery_plan();
        assert!(plan.supervision_lost());
        assert!(plan.requires_readback());
        let error = journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("runtime shutdown cannot expose premature recovery authority");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
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
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect_err("post-shutdown quiescence remains untrusted");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::WorkerTerminated
        ));
        assert_eq!(backend.remove_calls(), 0);
    }

    #[tokio::test]
    async fn debug_surfaces_redact_keys_addresses_selectors_and_spis() {
        let mut sa_request = sa_install_request();
        if let XfrmObjectInstallRequest::Sa(request) = &mut sa_request {
            request.parameters.auth = Some((
                crate::AuthAlgorithm::hmac_sha256(96),
                crate::KeyMaterial::new(vec![0xab; 32]),
            ));
        }
        let backend = Arc::new(GatedBackend::new());

        let staged = XfrmStagedObjectInstall::new(sa_request.clone());
        let journal = staged.journal();
        let empty_plan = journal.recovery_plan();
        let empty_classification = empty_plan.classification();
        let commit_error = journal
            .commit()
            .expect_err("unstarted runner cannot commit");
        let mut surfaces = vec![
            format!("{sa_request:?}"),
            format!("{staged:?}"),
            format!("{journal:?}"),
            format!("{empty_plan:?}"),
            format!("{empty_classification:?}"),
            format!("{commit_error:?}"),
            format!("{commit_error}"),
        ];
        staged.run(backend.clone()).await.expect("install applies");
        let plan = journal.recovery_plan();
        let classification = classify(&plan, XfrmResidueClassification::Owned);
        let candidate = plan
            .candidate()
            .expect("acknowledged install retains candidate");
        let missing = journal
            .recover(backend.clone(), plan.classification())
            .await
            .expect_err("missing classification is typed");
        surfaces.extend([
            format!("{plan:?}"),
            format!("{classification:?}"),
            format!("{candidate:?}"),
            format!("{:?}", journal.ownership()),
            format!("{missing:?}"),
            format!("{missing}"),
        ]);

        let policy_request = policy_install_request();
        let policy_backend = Arc::new(GatedBackend::new());
        policy_backend.lock().policy_present = true;
        let staged = XfrmStagedObjectInstall::new(policy_request.clone());
        let run_error = staged
            .run(policy_backend.clone())
            .await
            .expect_err("pre-existing policy rejects install");
        surfaces.extend([
            format!("{policy_request:?}"),
            format!("{run_error:?}"),
            format!("{run_error}"),
            format!("{:?}", XfrmObjectInstallOwnership::InstallInFlight),
            format!(
                "{:?}",
                XfrmObjectInstallOwnership::SupervisionLost { operation: None }
            ),
        ]);

        for surface in surfaces {
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

    #[tokio::test]
    async fn sa_removal_identity_preserves_the_lookup_mark() {
        let mark = XfrmMark {
            value: 0x42,
            mask: 0xffff_ffff,
        };
        let mut request = sa_install_request();
        if let XfrmObjectInstallRequest::Sa(request) = &mut request {
            request.parameters.mark = Some(mark);
        }
        let expected = RemoveSaRequest {
            mark: Some(mark),
            ..expected_remove_sa()
        };
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(request);
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        assert_eq!(
            plan.candidate(),
            Some(&XfrmObjectRemovalRequest::Sa(expected))
        );
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("owned classification removes the exact marked SA");
        assert_eq!(backend.removed_sa_requests(), vec![expected]);
    }

    #[tokio::test]
    async fn policy_removal_identity_preserves_the_lookup_mark() {
        let mark = XfrmMark {
            value: 0x77,
            mask: 0xffff_ffff,
        };
        let mut request = policy_install_request();
        if let XfrmObjectInstallRequest::Policy(request) = &mut request {
            request.parameters.mark = Some(mark);
        }
        let expected = RemovePolicyRequest {
            mark: Some(mark),
            ..expected_remove_policy()
        };
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(request);
        let journal = staged.journal();
        staged.run(backend.clone()).await.expect("install applies");

        let plan = journal.recovery_plan();
        assert_eq!(
            plan.candidate(),
            Some(&XfrmObjectRemovalRequest::Policy(expected.clone()))
        );
        journal
            .recover(
                backend.clone(),
                classify(&plan, XfrmResidueClassification::Owned),
            )
            .await
            .expect("owned classification removes the exact marked policy");
        assert_eq!(backend.removed_policy_requests(), vec![expected]);
    }

    /// Poll a future to completion without any Tokio runtime context.
    ///
    /// Only safe for futures that can never return `Poll::Pending` outside a
    /// runtime, such as the staged `run`/`recover` futures whose first
    /// statement is the runtime-presence check.
    fn block_on_without_runtime<F: Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn run_and_recover_outside_a_runtime_are_typed_and_do_not_poison_the_journal() {
        let backend = Arc::new(GatedBackend::new());
        let staged = XfrmStagedObjectInstall::new(sa_install_request());
        let journal = staged.journal();

        let error = block_on_without_runtime(staged.run(backend.clone()))
            .expect_err("run outside a runtime is typed");
        assert!(matches!(
            error,
            XfrmStagedObjectInstallRunError::RuntimeUnavailable
        ));
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);
        assert!(journal.recovery_plan().is_empty());
        assert!(backend.operations().is_empty());

        let error = block_on_without_runtime(
            journal.recover(backend.clone(), journal.recovery_plan().classification()),
        )
        .expect_err("recover outside a runtime is typed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RuntimeUnavailable
        ));
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::NotStarted);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            journal
                .recover(backend.clone(), journal.recovery_plan().classification())
                .await
                .expect("unpoisoned journal recovers inside a runtime");
        });
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);

        // A journal with live residue is likewise unpoisoned by a
        // runtime-free recovery attempt.
        let staged = XfrmStagedObjectInstall::new(policy_install_request());
        let journal = staged.journal();
        runtime.block_on(async {
            staged.run(backend.clone()).await.expect("install applies");
        });
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Acquired);
        let plan = journal.recovery_plan();
        let error = block_on_without_runtime(journal.recover(
            backend.clone(),
            classify(&plan, XfrmResidueClassification::Owned),
        ))
        .expect_err("recover outside a runtime is typed");
        assert!(matches!(
            error,
            XfrmObjectInstallRecoveryError::RuntimeUnavailable
        ));
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Acquired);
        assert_eq!(journal.recovery_plan(), plan);
        runtime.block_on(async {
            journal
                .recover(
                    backend.clone(),
                    classify(&plan, XfrmResidueClassification::Owned),
                )
                .await
                .expect("unpoisoned journal recovers inside a runtime");
        });
        assert_eq!(journal.ownership(), XfrmObjectInstallOwnership::Recovered);
        assert_eq!(
            backend.removed_policy_requests(),
            vec![expected_remove_policy()]
        );
    }
}
