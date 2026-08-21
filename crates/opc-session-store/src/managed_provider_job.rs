//! Immutable, server-owned provider jobs for fenced roster terminalization.
//!
//! This is the `/5` successor contract.  It deliberately has no wire codec:
//! a transport must authenticate its own closed DTO family before calling this
//! port.  The port separates durable effect-start recording from provider I/O,
//! so a restarted owner reconciles an uncertain effect instead of replaying it.

use std::{error::Error, fmt};

use async_trait::async_trait;

use crate::fenced_mutation_roster::FencedMutationRosterOrdinal;
use crate::{
    FencedMutationRosterAdmission, FencedMutationRosterMemberAttestation,
    FencedMutationRosterMemberAttestationError, FencedMutationRosterMemberAttestationVerifier,
    FencedMutationRosterMemberExecutionContext, FencedMutationRosterProviderOutcome,
    FencedMutationRosterRequestId, SessionConsumerIdentity, SessionConsumerScope,
};

/// The sole immutable managed-provider-job protocol revision.
pub const MANAGED_PROVIDER_JOB_V5_REVISION: u16 = 5;

/// Opaque authority to mutate one managed-provider-job scope.
///
/// Only the SDK consensus adapter can mint this value after it has admitted an
/// authenticated consumer scope and bound the configured server/verifier
/// identity.  It intentionally exposes neither the scope nor either identity
/// commitment: callers can pass it to the coordinator, but cannot select a
/// worker or widen its authority.
#[derive(Clone, Copy)]
pub struct ManagedProviderJobAuthority {
    scope: SessionConsumerScope,
    worker_identity_commitment: [u8; 32],
    verifier_identity_commitment: [u8; 32],
}

impl ManagedProviderJobAuthority {
    /// Mint authority only after authenticated server composition has checked
    /// the exact consumer scope and configured verifier identity.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub(crate) const fn from_authenticated_scope(
        scope: SessionConsumerScope,
        worker_identity_commitment: [u8; 32],
        verifier_identity_commitment: [u8; 32],
    ) -> Self {
        Self {
            scope,
            worker_identity_commitment,
            verifier_identity_commitment,
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn scope(self) -> SessionConsumerScope {
        self.scope
    }

    #[allow(dead_code)]
    pub(crate) const fn worker_identity_commitment(self) -> [u8; 32] {
        self.worker_identity_commitment
    }

    #[allow(dead_code)]
    pub(crate) const fn verifier_identity_commitment(self) -> [u8; 32] {
        self.verifier_identity_commitment
    }
}

impl fmt::Debug for ManagedProviderJobAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedProviderJobAuthority(<redacted>)")
    }
}

/// Durable roster execution mode.  Once selected it can never be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderJobMode {
    /// No terminal protocol has claimed this immutable roster yet.
    Unselected,
    /// The roster is owned by the managed `/5` job protocol.
    ManagedV5,
    /// A frozen predecessor terminal receipt won first; `/5` must not act.
    FrozenV4Terminal,
}

/// Durable state for one sibling member job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderJobMemberPhase {
    /// The effect has not been started.
    Ready,
    /// The durable effect boundary has been crossed; reconcile, never replay.
    EffectStarted,
    /// A server-verified private receipt is durable.
    Verified,
    /// The provider did not return conclusive reconciliation evidence.
    ReconciliationRequired,
    /// The member contributed to an established terminal receipt.
    Established,
    /// The immutable roster was aborted after conclusive reconciliation.
    Aborted,
}

/// Result of the atomic effect-start transition.
///
/// Only [`Self::Execute`] authorizes provider I/O.  Returning an existing
/// status is deliberately not an execution permit: a concurrent caller must
/// recover or observe the durable state instead of replaying the effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderJobEffectStart {
    /// This caller alone crossed `Ready -> EffectStarted` and may execute.
    Execute,
    /// Another caller already owns or completed the transition.
    Existing(ManagedProviderJobStatus),
}

/// Stable derived identity for a provider job.
///
/// The identity is `(admitted roster request ID, canonical member ordinal)`;
/// callers cannot select or replace it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManagedProviderJobId {
    roster: FencedMutationRosterRequestId,
    ordinal: FencedMutationRosterOrdinal,
}

impl ManagedProviderJobId {
    /// Derive the only legal member job identity for an admitted roster.
    pub const fn for_member(
        roster: FencedMutationRosterRequestId,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Self {
        Self { roster, ordinal }
    }

    /// Return the roster identity without exposing it through formatting.
    pub const fn roster(self) -> FencedMutationRosterRequestId {
        self.roster
    }

    /// Return the canonical member ordinal.
    pub const fn ordinal(self) -> FencedMutationRosterOrdinal {
        self.ordinal
    }
}

impl fmt::Debug for ManagedProviderJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedProviderJobId(<redacted>)")
    }
}

/// Redaction-safe public job status.  It deliberately carries no receipt or
/// provider evidence bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManagedProviderJobStatus {
    mode: ManagedProviderJobMode,
    phase: ManagedProviderJobMemberPhase,
}

impl ManagedProviderJobStatus {
    /// Construct one durable status.
    pub const fn new(mode: ManagedProviderJobMode, phase: ManagedProviderJobMemberPhase) -> Self {
        Self { mode, phase }
    }

    /// Return the immutable mode selection.
    pub const fn mode(self) -> ManagedProviderJobMode {
        self.mode
    }

    /// Return the durable member phase.
    pub const fn phase(self) -> ManagedProviderJobMemberPhase {
        self.phase
    }
}

impl fmt::Debug for ManagedProviderJobStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedProviderJobStatus")
            .field("mode", &self.mode)
            .field("phase", &self.phase)
            .finish()
    }
}

/// Conclusive remote observation used only after `EffectStarted` recovery.
#[derive(Clone, Copy)]
pub enum ManagedProviderMemberStatus {
    /// The provider proves the intended state exists; adopt it before receipt recording.
    Established,
    /// The provider proves it was compensated; adopt the compensated outcome.
    Compensated,
    /// The provider conclusively proves no effect was applied.  This roster is aborted.
    NotApplied,
    /// The provider cannot make a conclusive statement.
    Inconclusive,
}

/// Opaque conclusive reconciliation evidence.
///
/// A provider may report `Inconclusive` without evidence.  Every conclusive
/// status, including `NotApplied`, carries an attestation and is verified by
/// the configured verifier before it can alter durable state.
pub enum ManagedProviderMemberStatusEvidence {
    /// A verifier-bound provider observation for the exact member context.
    Attested(FencedMutationRosterMemberAttestation),
    /// The provider cannot make a conclusive statement.
    Inconclusive,
}

impl ManagedProviderMemberStatusEvidence {
    /// Wrap one conclusive provider attestation for verifier validation.
    pub const fn attested(attestation: FencedMutationRosterMemberAttestation) -> Self {
        Self::Attested(attestation)
    }
}

impl fmt::Debug for ManagedProviderMemberStatusEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attested(_) => {
                formatter.write_str("ManagedProviderMemberStatusEvidence(<redacted>)")
            }
            Self::Inconclusive => formatter.write_str("Inconclusive"),
        }
    }
}

impl fmt::Debug for ManagedProviderMemberStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Established => "Established",
            Self::Compensated => "Compensated",
            Self::NotApplied => "NotApplied",
            Self::Inconclusive => "Inconclusive",
        };
        formatter.write_str(name)
    }
}

/// Server-owned durable job errors.  None carries provider evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderJobError {
    /// The immutable roster belongs to a frozen predecessor terminal receipt.
    FrozenV4Terminal,
    /// A valid effect cannot be concluded without reconciliation.
    ReconciliationRequired,
    /// Conclusive not-applied evidence aborts this roster; a fresh admission is required.
    FreshAdmissionRequired,
    /// The configured verifier rejected a provider receipt.
    AttestationRejected,
    /// Durable state or an external port is unavailable; status recovery is required.
    Unavailable,
    /// The requested ordinal is not in the immutable admission.
    InvalidMember,
}

impl fmt::Display for ManagedProviderJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrozenV4Terminal => "managed provider job is closed by a frozen terminal receipt",
            Self::ReconciliationRequired => "managed provider job requires reconciliation",
            Self::FreshAdmissionRequired => {
                "managed provider job requires a fresh roster admission"
            }
            Self::AttestationRejected => "managed provider job attestation rejected",
            Self::Unavailable => "managed provider job is unavailable",
            Self::InvalidMember => "managed provider job member is invalid",
        })
    }
}

impl Error for ManagedProviderJobError {}

/// Successor remote provider port.  Implementations must bind all returned
/// attestations to the exact execution context and authenticated worker.
#[async_trait]
pub trait ManagedProviderJobRemoteProvider: Send + Sync {
    /// Opaque provider-side failure; it is never formatted by this module.
    type Error: Send + Sync + 'static;

    /// Execute a member only after the durable `EffectStarted` transition.
    async fn execute_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterMemberAttestation, Self::Error>;

    /// Reconcile an already-started member without performing the effect.
    async fn member_status(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<ManagedProviderMemberStatusEvidence, Self::Error>;

    /// Adopt one conclusive remote state and return its verifier-bound receipt.
    async fn adopt_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
        status: ManagedProviderMemberStatus,
    ) -> Result<FencedMutationRosterMemberAttestation, Self::Error>;
}

/// Durable authority port for managed `/5` jobs.
///
/// Implementations must atomically bind the immutable admission, checkpoint,
/// mTLS worker-identity commitment, and `ManagedV5` mode in `ensure_job`.
/// Receipt bytes remain private to the implementation; the public status only
/// reports phase and mode.
#[async_trait]
pub trait ManagedProviderJobStore: Send + Sync {
    /// Store failure, intentionally rendered only as `Unavailable` by the coordinator.
    type Error: Send + Sync + 'static;

    /// Atomically select `/5` mode and bind the exact immutable admission.
    async fn ensure_job(
        &self,
        admission: &FencedMutationRosterAdmission,
        checkpoint: &[u8],
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;

    /// Read one durable sibling job status.
    async fn job_status(
        &self,
        id: ManagedProviderJobId,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;

    /// Atomically cross the effect boundary exactly once.
    async fn mark_member_effect_started(
        &self,
        id: ManagedProviderJobId,
    ) -> Result<ManagedProviderJobEffectStart, Self::Error>;

    /// Persist only a private verifier-authenticated receipt/digest.
    async fn record_verified_attestation(
        &self,
        id: ManagedProviderJobId,
        outcome: FencedMutationRosterProviderOutcome,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;

    /// Build terminal state from private durable receipts using the existing terminal CAS.
    async fn finalize_job(
        &self,
        admission: &FencedMutationRosterAdmission,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;

    /// Recover only already-owned nonterminal jobs.  It never creates jobs.
    async fn recover_owned_jobs(&self) -> Result<Box<[ManagedProviderJobId]>, Self::Error>;

    /// Abort after conclusive not-applied evidence.  The immutable roster may not restart.
    async fn abort_not_applied(
        &self,
        id: ManagedProviderJobId,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;

    /// Record that reconciliation is required without exposing external detail.
    async fn require_reconciliation(
        &self,
        id: ManagedProviderJobId,
    ) -> Result<ManagedProviderJobStatus, Self::Error>;
}

/// Server-side `/5` coordinator.  It owns no provider identity or verifier
/// configuration; those are injected only by the authenticated server port.
pub struct ManagedProviderJobCoordinator<'a, S, P, V: ?Sized> {
    store: &'a S,
    provider: &'a P,
    verifier: &'a V,
    worker: &'a SessionConsumerIdentity,
    authority: ManagedProviderJobAuthority,
}

impl<'a, S, P, V> ManagedProviderJobCoordinator<'a, S, P, V>
where
    S: ManagedProviderJobStore,
    P: ManagedProviderJobRemoteProvider,
    V: FencedMutationRosterMemberAttestationVerifier + ?Sized,
{
    /// Construct a server-owned coordinator after mTLS has supplied the worker identity.
    pub const fn new(
        store: &'a S,
        provider: &'a P,
        verifier: &'a V,
        worker: &'a SessionConsumerIdentity,
        authority: ManagedProviderJobAuthority,
    ) -> Self {
        Self {
            store,
            provider,
            verifier,
            worker,
            authority,
        }
    }

    /// Ensure durable ownership before any provider I/O, then execute or reconcile one member.
    pub async fn run_member(
        &self,
        admission: &FencedMutationRosterAdmission,
        checkpoint: &[u8],
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
        let ensured = self
            .store
            .ensure_job(admission, checkpoint, self.authority)
            .await
            .map_err(|_| ManagedProviderJobError::Unavailable)?;
        if ensured.mode() == ManagedProviderJobMode::FrozenV4Terminal {
            return Err(ManagedProviderJobError::FrozenV4Terminal);
        }
        if ensured.mode() != ManagedProviderJobMode::ManagedV5 {
            return Err(ManagedProviderJobError::Unavailable);
        }
        let context =
            FencedMutationRosterMemberExecutionContext::for_admission_member(admission, ordinal)
                .map_err(|_| ManagedProviderJobError::InvalidMember)?;
        let id = ManagedProviderJobId::for_member(admission.request_id(), ordinal);
        let status = self
            .store
            .job_status(id)
            .await
            .map_err(|_| ManagedProviderJobError::Unavailable)?;
        match status.phase() {
            ManagedProviderJobMemberPhase::Ready => {
                let started = self
                    .store
                    .mark_member_effect_started(id)
                    .await
                    .map_err(|_| ManagedProviderJobError::Unavailable)?;
                if matches!(started, ManagedProviderJobEffectStart::Execute) {
                    let attestation = self
                        .provider
                        .execute_member(&context)
                        .await
                        .map_err(|_| ManagedProviderJobError::ReconciliationRequired)?;
                    self.verify_record_and_finalize(admission, id, &context, attestation)
                        .await
                } else if let ManagedProviderJobEffectStart::Existing(status) = started {
                    Ok(status)
                } else {
                    Err(ManagedProviderJobError::Unavailable)
                }
            }
            ManagedProviderJobMemberPhase::EffectStarted => {
                self.reconcile(admission, id, &context).await
            }
            ManagedProviderJobMemberPhase::Verified => self
                .store
                .finalize_job(admission)
                .await
                .map_err(|_| ManagedProviderJobError::Unavailable),
            ManagedProviderJobMemberPhase::ReconciliationRequired => {
                Err(ManagedProviderJobError::ReconciliationRequired)
            }
            ManagedProviderJobMemberPhase::Established | ManagedProviderJobMemberPhase::Aborted => {
                Ok(status)
            }
        }
    }

    async fn reconcile(
        &self,
        admission: &FencedMutationRosterAdmission,
        id: ManagedProviderJobId,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
        match self
            .provider
            .member_status(context)
            .await
            .map_err(|_| ManagedProviderJobError::ReconciliationRequired)?
        {
            ManagedProviderMemberStatusEvidence::Attested(attestation) => {
                attestation
                    .validate_for(context)
                    .map_err(|_| ManagedProviderJobError::AttestationRejected)?;
                let outcome = self
                    .verifier
                    .verify_member_attestation(self.worker, context, &attestation)
                    .await
                    .map_err(map_verifier_error)?;
                if outcome != attestation.outcome() {
                    return Err(ManagedProviderJobError::AttestationRejected);
                }
                match outcome {
                    FencedMutationRosterProviderOutcome::NotAppliedReconciled => {
                        self.store
                            .abort_not_applied(id)
                            .await
                            .map_err(|_| ManagedProviderJobError::Unavailable)?;
                        Err(ManagedProviderJobError::FreshAdmissionRequired)
                    }
                    FencedMutationRosterProviderOutcome::AppliedExecuted
                    | FencedMutationRosterProviderOutcome::AppliedAdopted
                    | FencedMutationRosterProviderOutcome::CompensatedReconciled => {
                        self.store
                            .record_verified_attestation(id, outcome)
                            .await
                            .map_err(|_| ManagedProviderJobError::Unavailable)?;
                        self.store
                            .finalize_job(admission)
                            .await
                            .map_err(|_| ManagedProviderJobError::Unavailable)
                    }
                }
            }
            ManagedProviderMemberStatusEvidence::Inconclusive => {
                self.store
                    .require_reconciliation(id)
                    .await
                    .map_err(|_| ManagedProviderJobError::Unavailable)?;
                Err(ManagedProviderJobError::ReconciliationRequired)
            }
        }
    }

    async fn verify_record_and_finalize(
        &self,
        admission: &FencedMutationRosterAdmission,
        id: ManagedProviderJobId,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
        attestation: FencedMutationRosterMemberAttestation,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
        attestation
            .validate_for(context)
            .map_err(|_| ManagedProviderJobError::AttestationRejected)?;
        let outcome = self
            .verifier
            .verify_member_attestation(self.worker, context, &attestation)
            .await
            .map_err(map_verifier_error)?;
        if outcome != attestation.outcome() {
            return Err(ManagedProviderJobError::AttestationRejected);
        }
        match self.store.record_verified_attestation(id, outcome).await {
            Ok(_) => self
                .store
                .finalize_job(admission)
                .await
                .map_err(|_| ManagedProviderJobError::Unavailable),
            // The write outcome is deliberately resolved through durable status; the
            // provider effect and verifier are never retried from this branch.
            Err(_) => self
                .store
                .job_status(id)
                .await
                .map_err(|_| ManagedProviderJobError::Unavailable),
        }
    }
}

fn map_verifier_error(
    error: FencedMutationRosterMemberAttestationError,
) -> ManagedProviderJobError {
    match error {
        FencedMutationRosterMemberAttestationError::Rejected => {
            ManagedProviderJobError::AttestationRejected
        }
        FencedMutationRosterMemberAttestationError::Unavailable => {
            ManagedProviderJobError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use crate::fenced_mutation_roster::{
        FencedMutationRosterAdoption, FencedMutationRosterDescriptor,
        FencedMutationRosterDisposition,
    };
    use crate::{
        FenceToken, FencedMutationRosterFenceIntent, FencedMutationRosterMember,
        FencedMutationRosterMembers, FencedMutationRosterOperationId,
        FencedMutationRosterProtectedPlan, FencedMutationRosterScope, Generation, OwnerId,
    };

    struct State {
        mode: ManagedProviderJobMode,
        phase: ManagedProviderJobMemberPhase,
        lose_record_ack: bool,
    }

    struct Store(Mutex<State>);

    #[derive(Debug)]
    struct StoreWriteLost;

    impl fmt::Display for StoreWriteLost {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test store write acknowledgement lost")
        }
    }

    impl Error for StoreWriteLost {}

    #[async_trait]
    impl ManagedProviderJobStore for Store {
        type Error = StoreWriteLost;

        async fn ensure_job(
            &self,
            _admission: &FencedMutationRosterAdmission,
            _checkpoint: &[u8],
            _authority: ManagedProviderJobAuthority,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let state = self.0.lock().expect("test state lock");
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }

        async fn job_status(
            &self,
            _id: ManagedProviderJobId,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let state = self.0.lock().expect("test state lock");
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }

        async fn mark_member_effect_started(
            &self,
            _id: ManagedProviderJobId,
        ) -> Result<ManagedProviderJobEffectStart, Self::Error> {
            let mut state = self.0.lock().expect("test state lock");
            if state.phase == ManagedProviderJobMemberPhase::Ready {
                state.phase = ManagedProviderJobMemberPhase::EffectStarted;
                return Ok(ManagedProviderJobEffectStart::Execute);
            }
            Ok(ManagedProviderJobEffectStart::Existing(
                ManagedProviderJobStatus::new(state.mode, state.phase),
            ))
        }

        async fn record_verified_attestation(
            &self,
            _id: ManagedProviderJobId,
            _outcome: FencedMutationRosterProviderOutcome,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let mut state = self.0.lock().expect("test state lock");
            state.phase = ManagedProviderJobMemberPhase::Verified;
            if state.lose_record_ack {
                return Err(StoreWriteLost);
            }
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }

        async fn finalize_job(
            &self,
            _admission: &FencedMutationRosterAdmission,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let mut state = self.0.lock().expect("test state lock");
            if state.phase == ManagedProviderJobMemberPhase::Verified {
                state.phase = ManagedProviderJobMemberPhase::Established;
            }
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }

        async fn recover_owned_jobs(&self) -> Result<Box<[ManagedProviderJobId]>, Self::Error> {
            Ok(Box::new([]))
        }

        async fn abort_not_applied(
            &self,
            _id: ManagedProviderJobId,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let mut state = self.0.lock().expect("test state lock");
            state.phase = ManagedProviderJobMemberPhase::Aborted;
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }

        async fn require_reconciliation(
            &self,
            _id: ManagedProviderJobId,
        ) -> Result<ManagedProviderJobStatus, Self::Error> {
            let mut state = self.0.lock().expect("test state lock");
            state.phase = ManagedProviderJobMemberPhase::ReconciliationRequired;
            Ok(ManagedProviderJobStatus::new(state.mode, state.phase))
        }
    }

    struct Provider {
        executes: AtomicUsize,
        status: ManagedProviderMemberStatus,
        adopts: AtomicUsize,
    }

    #[async_trait]
    impl ManagedProviderJobRemoteProvider for Provider {
        type Error = Infallible;

        async fn execute_member(
            &self,
            context: &FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<FencedMutationRosterMemberAttestation, Self::Error> {
            self.executes.fetch_add(1, Ordering::Relaxed);
            FencedMutationRosterMemberAttestation::new(
                context,
                FencedMutationRosterProviderOutcome::AppliedExecuted,
                Box::new([0xa5]),
            )
            .map_err(|_| unreachable!("fixed test attestation is valid"))
        }

        async fn member_status(
            &self,
            context: &FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<ManagedProviderMemberStatusEvidence, Self::Error> {
            let outcome = match self.status {
                ManagedProviderMemberStatus::Established => {
                    FencedMutationRosterProviderOutcome::AppliedAdopted
                }
                ManagedProviderMemberStatus::Compensated => {
                    FencedMutationRosterProviderOutcome::CompensatedReconciled
                }
                ManagedProviderMemberStatus::NotApplied => {
                    FencedMutationRosterProviderOutcome::NotAppliedReconciled
                }
                ManagedProviderMemberStatus::Inconclusive => {
                    return Ok(ManagedProviderMemberStatusEvidence::Inconclusive);
                }
            };
            let attestation =
                FencedMutationRosterMemberAttestation::new(context, outcome, Box::new([0x5a]))
                    .unwrap_or_else(|_| unreachable!("fixed test attestation is valid"));
            Ok(ManagedProviderMemberStatusEvidence::attested(attestation))
        }

        async fn adopt_member(
            &self,
            context: &FencedMutationRosterMemberExecutionContext<'_>,
            status: ManagedProviderMemberStatus,
        ) -> Result<FencedMutationRosterMemberAttestation, Self::Error> {
            self.adopts.fetch_add(1, Ordering::Relaxed);
            let outcome = match status {
                ManagedProviderMemberStatus::Established => {
                    FencedMutationRosterProviderOutcome::AppliedAdopted
                }
                ManagedProviderMemberStatus::Compensated => {
                    FencedMutationRosterProviderOutcome::CompensatedReconciled
                }
                ManagedProviderMemberStatus::NotApplied
                | ManagedProviderMemberStatus::Inconclusive => {
                    unreachable!("only conclusive adopt status reaches provider")
                }
            };
            FencedMutationRosterMemberAttestation::new(context, outcome, Box::new([0x5a]))
                .map_err(|_| unreachable!("fixed test attestation is valid"))
        }
    }

    struct Verifier;

    #[async_trait]
    impl FencedMutationRosterMemberAttestationVerifier for Verifier {
        async fn verify_member_attestation(
            &self,
            _identity: &SessionConsumerIdentity,
            context: &FencedMutationRosterMemberExecutionContext<'_>,
            attestation: &FencedMutationRosterMemberAttestation,
        ) -> Result<FencedMutationRosterProviderOutcome, FencedMutationRosterMemberAttestationError>
        {
            attestation
                .validate_for(context)
                .map_err(|_| FencedMutationRosterMemberAttestationError::Rejected)?;
            Ok(attestation.outcome())
        }
    }

    fn admission() -> FencedMutationRosterAdmission {
        let member = FencedMutationRosterMember::new(
            FencedMutationRosterOrdinal::new(0).expect("bounded ordinal"),
            [1; 16],
            FencedMutationRosterDescriptor::new(Vec::new()).expect("bounded descriptor"),
            1,
            1,
            FencedMutationRosterDisposition::Pending,
            FencedMutationRosterAdoption::Unreconciled,
        )
        .expect("valid member");
        FencedMutationRosterAdmission::new(
            1,
            FencedMutationRosterOperationId::new([2; 16]).expect("nonzero operation"),
            FencedMutationRosterScope::from_digest([3; 32]),
            FencedMutationRosterFenceIntent::new(
                OwnerId::new("test-owner").expect("owner"),
                FenceToken::new(1),
            ),
            Generation::new(1),
            FencedMutationRosterMembers::new([member]).expect("manifest"),
            FencedMutationRosterProtectedPlan::new(Box::new([])).expect("plan"),
        )
        .expect("admission")
    }

    fn coordinator<'a>(
        store: &'a Store,
        provider: &'a Provider,
    ) -> ManagedProviderJobCoordinator<'a, Store, Provider, Verifier> {
        static VERIFIER: Verifier = Verifier;
        let identity = Box::leak(Box::new(
            SessionConsumerIdentity::new("spiffe://test/worker").expect("identity"),
        ));
        let authority = ManagedProviderJobAuthority::from_authenticated_scope(
            SessionConsumerScope::new(crate::consensus::SessionConsensusIdentity::new(
                crate::consensus::SessionConsensusClusterId::new("test-cluster").expect("cluster"),
                crate::consensus::SessionConsensusConfigurationId::from_bytes([5; 32]),
                crate::consensus::SessionConsensusConfigurationEpoch::new(1).expect("epoch"),
            )),
            [4; 32],
            [6; 32],
        );
        ManagedProviderJobCoordinator::new(store, provider, &VERIFIER, identity, authority)
    }

    #[test]
    fn authority_debug_is_redacted() {
        let authority = ManagedProviderJobAuthority::from_authenticated_scope(
            SessionConsumerScope::new(crate::consensus::SessionConsensusIdentity::new(
                crate::consensus::SessionConsensusClusterId::new("test-cluster").expect("cluster"),
                crate::consensus::SessionConsensusConfigurationId::from_bytes([7; 32]),
                crate::consensus::SessionConsensusConfigurationEpoch::new(1).expect("epoch"),
            )),
            [8; 32],
            [9; 32],
        );
        assert_eq!(
            format!("{authority:?}"),
            "ManagedProviderJobAuthority(<redacted>)"
        );
    }

    #[tokio::test]
    async fn only_one_effect_start_caller_receives_execution_permit() {
        let store = Store(Mutex::new(State {
            mode: ManagedProviderJobMode::ManagedV5,
            phase: ManagedProviderJobMemberPhase::Ready,
            lose_record_ack: false,
        }));
        let id = ManagedProviderJobId::for_member(
            admission().request_id(),
            FencedMutationRosterOrdinal::new(0).expect("ordinal"),
        );
        assert_eq!(
            store
                .mark_member_effect_started(id)
                .await
                .expect("first durable start"),
            ManagedProviderJobEffectStart::Execute
        );
        assert_eq!(
            store
                .mark_member_effect_started(id)
                .await
                .expect("second durable observation"),
            ManagedProviderJobEffectStart::Existing(ManagedProviderJobStatus::new(
                ManagedProviderJobMode::ManagedV5,
                ManagedProviderJobMemberPhase::EffectStarted,
            ))
        );
    }

    #[tokio::test]
    async fn frozen_predecessor_terminal_never_calls_provider() {
        let store = Store(Mutex::new(State {
            mode: ManagedProviderJobMode::FrozenV4Terminal,
            phase: ManagedProviderJobMemberPhase::Aborted,
            lose_record_ack: false,
        }));
        let provider = Provider {
            executes: AtomicUsize::new(0),
            status: ManagedProviderMemberStatus::Inconclusive,
            adopts: AtomicUsize::new(0),
        };
        let result = coordinator(&store, &provider)
            .run_member(
                &admission(),
                &[],
                FencedMutationRosterOrdinal::new(0).expect("ordinal"),
            )
            .await;
        assert_eq!(result, Err(ManagedProviderJobError::FrozenV4Terminal));
        assert_eq!(provider.executes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn effect_started_recovery_uses_attested_status_without_reexecution() {
        let store = Store(Mutex::new(State {
            mode: ManagedProviderJobMode::ManagedV5,
            phase: ManagedProviderJobMemberPhase::EffectStarted,
            lose_record_ack: false,
        }));
        let provider = Provider {
            executes: AtomicUsize::new(0),
            status: ManagedProviderMemberStatus::Established,
            adopts: AtomicUsize::new(0),
        };
        let result = coordinator(&store, &provider)
            .run_member(
                &admission(),
                &[],
                FencedMutationRosterOrdinal::new(0).expect("ordinal"),
            )
            .await
            .expect("verifies status and finalizes");
        assert_eq!(result.phase(), ManagedProviderJobMemberPhase::Established);
        assert_eq!(provider.executes.load(Ordering::Relaxed), 0);
        assert_eq!(provider.adopts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn not_applied_recovery_requires_fresh_admission() {
        let store = Store(Mutex::new(State {
            mode: ManagedProviderJobMode::ManagedV5,
            phase: ManagedProviderJobMemberPhase::EffectStarted,
            lose_record_ack: false,
        }));
        let provider = Provider {
            executes: AtomicUsize::new(0),
            status: ManagedProviderMemberStatus::NotApplied,
            adopts: AtomicUsize::new(0),
        };
        let result = coordinator(&store, &provider)
            .run_member(
                &admission(),
                &[],
                FencedMutationRosterOrdinal::new(0).expect("ordinal"),
            )
            .await;
        assert_eq!(result, Err(ManagedProviderJobError::FreshAdmissionRequired));
        assert_eq!(provider.executes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn unknown_receipt_write_is_resolved_by_status_without_provider_replay() {
        let store = Store(Mutex::new(State {
            mode: ManagedProviderJobMode::ManagedV5,
            phase: ManagedProviderJobMemberPhase::Ready,
            lose_record_ack: true,
        }));
        let provider = Provider {
            executes: AtomicUsize::new(0),
            status: ManagedProviderMemberStatus::Inconclusive,
            adopts: AtomicUsize::new(0),
        };
        let status = coordinator(&store, &provider)
            .run_member(
                &admission(),
                &[],
                FencedMutationRosterOrdinal::new(0).expect("ordinal"),
            )
            .await
            .expect("durable status resolves a lost receipt acknowledgement");
        assert_eq!(status.phase(), ManagedProviderJobMemberPhase::Verified);
        assert_eq!(provider.executes.load(Ordering::Relaxed), 1);
        assert!(!format!("{status:?}").contains("a5"));
    }
}
