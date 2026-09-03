//! Provider-local publication adapter for established fenced-mutation rosters.
//!
//! Publication intentionally sits after terminalization. It does not append a
//! third roster command: a narrow, read-only backend current-authority reader
//! and a shared startup-owned local authority permit are checked immediately
//! before and after each provider operation. The provider owns the idempotency journal keyed by
//! [`super::canonical::PublicationId`]; this adapter never creates a
//! per-caller task, channel, connection, or durable consensus record.

use super::{
    canonical::{
        EstablishedPublicationCall, EstablishedPublicationProvider, PublicationEvidence,
        PublicationProviderOutcome,
    },
    client::{EstablishedPublication, PublicationState},
    diagnostics::{Counter as DiagnosticsCounter, RosterDiagnostics},
    runtime::{
        CurrentPublicationAuthorityRead, LocalAuthorityRegistry, PublicationAuthorityReader,
    },
    scheduler::ProviderWorkScheduler,
};
use std::{fmt, sync::Arc, time::Duration};

/// This is deliberately the same finite provider-effect budget used by the
/// roster executor. A timeout is an ambiguity boundary, not conclusive
/// non-transmission of an intent or external effect.
const PUBLICATION_EFFECT_DEADLINE: Duration = Duration::from_secs(30);

/// Fixed, redaction-safe publication result classification.
///
/// No variant carries a backend error, provider error, identifier, protected
/// bytes, or evidence.  In particular, callers must not infer that an unknown
/// result was absent and must recover through `status`/`adopt`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PublicationAdapterError {
    /// The established capability is no longer the current half-open lease
    /// authority at the pre-effect read barrier.
    AuthorityRejected,
    /// The effect may have crossed, its reply was invalid, or the post-effect
    /// authority barrier did not prove that this exact capability remains
    /// current.  Recover with provider `status` and, where applicable, `adopt`.
    RecoveryRequired,
    /// Shared process-wide provider capacity is currently exhausted.
    Busy,
    /// The provider retained this stable publication identity with different
    /// checkpoint/result/receipt commitments.
    PayloadConflict,
    /// The provider-local intent-admission call definitely did not transmit.
    ///
    /// This authorizes retrying only the same retained publication capsule's
    /// exact effect-free intent admission. It never authorizes replaying the
    /// external publication effect.
    BeginNotTransmitted,
    /// The compound fresh-publication request definitely did not reserve or
    /// attempt the provider journal entry.
    ///
    /// This authorizes retrying only the same opaque fresh publication capsule
    /// through the dedicated fresh-publication API. It never authorizes a
    /// recovered or status-derived capsule to execute.
    FreshNotTransmitted,
}

impl fmt::Display for PublicationAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorityRejected => "publication authority rejected",
            Self::RecoveryRequired => "publication recovery required",
            Self::Busy => "publication provider busy",
            Self::PayloadConflict => "publication payload conflict",
            Self::BeginNotTransmitted => "publication intent admission not transmitted",
            Self::FreshNotTransmitted => "fresh publication request not transmitted",
        })
    }
}

impl std::error::Error for PublicationAdapterError {}

/// Startup-owned provider-local publication seam.
///
/// Clones share the exact provider, backend-current authority reader, local
/// authority registry, and bounded scheduler selected at process startup.
/// Fresh success remains exactly the admission write plus the terminalization
/// write.
pub(crate) struct PublicationAdapter<P, A> {
    provider: Arc<P>,
    authority_reader: Arc<A>,
    scheduler: ProviderWorkScheduler,
    local_authority: LocalAuthorityRegistry,
    diagnostics: RosterDiagnostics,
}

impl<P, A> Clone for PublicationAdapter<P, A> {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
            authority_reader: Arc::clone(&self.authority_reader),
            scheduler: self.scheduler.clone(),
            local_authority: self.local_authority.clone(),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

impl<P, A> fmt::Debug for PublicationAdapter<P, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationAdapter(<redacted>)")
    }
}

impl<P, A> PublicationAdapter<P, A>
where
    P: EstablishedPublicationProvider,
    A: PublicationAuthorityReader,
{
    /// Construct an adapter from the same startup-owned arcs and scheduler as
    /// the roster executor.  This module deliberately cannot accept a provider
    /// on an individual publish request.
    pub(crate) fn new(
        provider: Arc<P>,
        authority_reader: Arc<A>,
        scheduler: ProviderWorkScheduler,
        local_authority: LocalAuthorityRegistry,
        diagnostics: RosterDiagnostics,
    ) -> Self {
        Self {
            provider,
            authority_reader,
            scheduler,
            local_authority,
            diagnostics,
        }
    }

    /// Publish the exact established terminal payload, or return a
    /// redaction-safe recovery classification without acknowledging it.
    ///
    /// The caller supplies an opaque SDK-issued established publication, which
    /// binds the stable [`super::canonical::PublicationId`] to the
    /// roster, admission commitment, terminal commitment, receipt commitment,
    /// and exact checkpoint/result bytes.  Its stable ID deliberately excludes
    /// replaceable current successor authority; authority is instead checked
    /// by backend-current and shared startup-owned local permit validation
    /// around every provider effect.
    pub(crate) async fn publish(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        let scheduling_digest = match EstablishedPublicationCall::from_established(publication) {
            Ok(call) => {
                super::runtime::provider_scheduling_digest(call.authority().current_authority())
            }
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::PublicationRecoveryRequired);
                return Err(PublicationAdapterError::RecoveryRequired);
            }
        };
        let _permit = match self.scheduler.try_acquire(scheduling_digest) {
            Ok(permit) => permit,
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::PublicationProviderBusy);
                return Err(PublicationAdapterError::Busy);
            }
        };

        let result = match publication.state() {
            // A newly materialized or recovered terminal has no process-local
            // evidence about earlier publication work. It can only discover
            // or durably admit the same effect-free provider intent.
            PublicationState::FreshCompound | PublicationState::Unclassified => {
                self.publish_unclassified(publication).await
            }
            // Only the effect-free intent admission may be retransmitted, and
            // only after that exact call proved it did not cross transport.
            PublicationState::DirectBeginRetry => self.begin_publication(publication).await,
            // Any ambiguity, pending intent, or untrusted absence is forever
            // restricted to provider status/adopt operations.
            PublicationState::DirectFreshRetry | PublicationState::StatusAdoptOnly => {
                self.status_or_adopt(publication).await
            }
        };
        if matches!(result, Err(PublicationAdapterError::RecoveryRequired)) {
            self.diagnostics
                .increment(DiagnosticsCounter::PublicationRecoveryRequired);
        }
        result
    }

    /// Publish a directly terminalized Established capsule through one
    /// provider-owned status/reserve/attempt/adopt operation.
    ///
    /// This is intentionally separate from [`Self::publish`]. The provider
    /// must implement the compound journal contract on
    /// [`EstablishedPublicationProvider::publish_fresh_established`]; the
    /// SDK wraps that one call in exactly one pre-effect and one post-effect
    /// backend-current authority validation. Reconstructed/status-only
    /// capsules fall back to status/adopt and never receive compound effect
    /// authority.
    pub(crate) async fn publish_fresh_established(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        let scheduling_digest = match EstablishedPublicationCall::from_established(publication) {
            Ok(call) => {
                super::runtime::provider_scheduling_digest(call.authority().current_authority())
            }
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::PublicationRecoveryRequired);
                return Err(PublicationAdapterError::RecoveryRequired);
            }
        };
        let _permit = match self.scheduler.try_acquire(scheduling_digest) {
            Ok(permit) => permit,
            Err(_) => {
                self.diagnostics
                    .increment(DiagnosticsCounter::PublicationProviderBusy);
                return Err(PublicationAdapterError::Busy);
            }
        };

        let result = match publication.state() {
            PublicationState::FreshCompound | PublicationState::DirectFreshRetry => {
                self.publish_fresh_compound(publication).await
            }
            // A recovery/status result cannot reconstruct fresh effect
            // authority. It may only observe/adopt the same retained ID.
            PublicationState::Unclassified
            | PublicationState::DirectBeginRetry
            | PublicationState::StatusAdoptOnly => self.status_or_adopt(publication).await,
        };
        if matches!(result, Err(PublicationAdapterError::RecoveryRequired)) {
            self.diagnostics
                .increment(DiagnosticsCounter::PublicationRecoveryRequired);
        }
        result
    }

    async fn publish_fresh_compound(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        // This write precedes the first await. Dropping a future once the
        // provider has the call can never leave its capsule able to launch a
        // second compound effect; recovery is status/adopt-only.
        publication.set_state(PublicationState::StatusAdoptOnly);
        let outcome = self.invoke_fresh_publication(publication).await?;
        match outcome {
            PublicationProviderOutcome::Published(evidence) => self.ack(publication, evidence),
            PublicationProviderOutcome::FreshNotTransmitted => {
                publication.set_state(PublicationState::DirectFreshRetry);
                Err(PublicationAdapterError::FreshNotTransmitted)
            }
            PublicationProviderOutcome::Pending(evidence) => {
                self.validate_evidence(publication, &evidence)?;
                Err(PublicationAdapterError::RecoveryRequired)
            }
            // A compound operation must not turn absence or ambiguity into
            // fresh authority. Both are recovered by status/adopt only.
            PublicationProviderOutcome::Absent
            | PublicationProviderOutcome::NotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown => {
                Err(PublicationAdapterError::RecoveryRequired)
            }
            PublicationProviderOutcome::Conflict => Err(PublicationAdapterError::PayloadConflict),
        }
    }

    async fn publish_unclassified(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        match self.status(publication).await? {
            PublicationProviderOutcome::Published(evidence) => self.ack(publication, evidence),
            // Absence is never external-effect authority. It permits only the
            // provider-local durable intent admission, whose contract forbids
            // crossing the publication boundary.
            PublicationProviderOutcome::Absent => self.begin_publication(publication).await,
            PublicationProviderOutcome::Pending(evidence) => {
                self.validate_evidence(publication, &evidence)?;
                self.adopt_pending(publication).await
            }
            PublicationProviderOutcome::Conflict => Err(PublicationAdapterError::PayloadConflict),
            PublicationProviderOutcome::NotTransmitted
            | PublicationProviderOutcome::FreshNotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown => {
                publication.set_state(PublicationState::StatusAdoptOnly);
                Err(PublicationAdapterError::RecoveryRequired)
            }
        }
    }

    async fn status_or_adopt(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        match self.status(publication).await? {
            PublicationProviderOutcome::Published(evidence) => self.ack(publication, evidence),
            PublicationProviderOutcome::Pending(evidence) => {
                self.validate_evidence(publication, &evidence)?;
                self.adopt_pending(publication).await
            }
            // Absence after an ambiguity is deliberately non-exclusionary. It
            // cannot authorize a second intent, a replacement ID, or altered
            // terminal bytes, and can never authorize an external effect.
            PublicationProviderOutcome::Absent
            | PublicationProviderOutcome::NotTransmitted
            | PublicationProviderOutcome::FreshNotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown => {
                Err(PublicationAdapterError::RecoveryRequired)
            }
            PublicationProviderOutcome::Conflict => Err(PublicationAdapterError::PayloadConflict),
        }
    }

    /// Durably create or recover the exact provider-local publication intent.
    ///
    /// This call is forbidden from crossing the external publication effect
    /// boundary. Only `adopt_pending` may reconcile or finish that effect, so
    /// reconstructing an Established receipt can never recreate blind-run
    /// authority after an earlier ambiguous publication.
    async fn begin_publication(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        // Set recovery-only before the first await. A cancelled future, a
        // timeout, an invalid reply, or a stale postcheck can never leave a
        // caller with implicit intent-admission retry authority.
        publication.set_state(PublicationState::StatusAdoptOnly);
        let outcome = self
            .invoke_publication(PublicationOperation::Begin, publication)
            .await?;
        match outcome {
            PublicationProviderOutcome::Published(evidence) => self.ack(publication, evidence),
            // This is the one response that preserves retry authority, only
            // for the exact effect-free intent admission retained here.
            PublicationProviderOutcome::NotTransmitted => {
                publication.set_state(PublicationState::DirectBeginRetry);
                self.diagnostics
                    .increment(DiagnosticsCounter::PublicationBeginNotTransmitted);
                Err(PublicationAdapterError::BeginNotTransmitted)
            }
            // An intent is only useful through the adoption/reconciliation
            // path. The SDK validates its exact evidence before that effect.
            PublicationProviderOutcome::Pending(evidence) => {
                self.validate_evidence(publication, &evidence)?;
                self.adopt_pending(publication).await
            }
            // Absence after begin is nonconclusive and can never restore even
            // effect-free retry authority without a direct non-transmission.
            PublicationProviderOutcome::Absent
            | PublicationProviderOutcome::FreshNotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown => {
                Err(PublicationAdapterError::RecoveryRequired)
            }
            PublicationProviderOutcome::Conflict => Err(PublicationAdapterError::PayloadConflict),
        }
    }

    /// Pending is a recovery state.  It can only become an ACK after a
    /// provider-local adoption/status result proves the exact same capsule.
    async fn adopt_pending(
        &self,
        publication: &mut EstablishedPublication,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        publication.set_state(PublicationState::StatusAdoptOnly);
        let outcome = self
            .invoke_publication(PublicationOperation::Adopt, publication)
            .await?;
        match outcome {
            PublicationProviderOutcome::Published(evidence) => self.ack(publication, evidence),
            PublicationProviderOutcome::Conflict => Err(PublicationAdapterError::PayloadConflict),
            PublicationProviderOutcome::Absent
            | PublicationProviderOutcome::NotTransmitted
            | PublicationProviderOutcome::FreshNotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown => {
                Err(PublicationAdapterError::RecoveryRequired)
            }
            PublicationProviderOutcome::Pending(evidence) => {
                self.validate_evidence(publication, &evidence)?;
                Err(PublicationAdapterError::RecoveryRequired)
            }
        }
    }

    async fn status(
        &self,
        publication: &EstablishedPublication,
    ) -> Result<PublicationProviderOutcome, PublicationAdapterError> {
        self.invoke_publication(PublicationOperation::Status, publication)
            .await
    }

    /// Validate provider evidence before it can drive a recovery transition or
    /// become a caller-visible publication acknowledgement.
    fn validate_evidence(
        &self,
        publication: &EstablishedPublication,
        evidence: &PublicationEvidence,
    ) -> Result<(), PublicationAdapterError> {
        let call = EstablishedPublicationCall::from_established(publication)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        evidence
            .validate_for(&call)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)
    }

    fn ack(
        &self,
        publication: &EstablishedPublication,
        evidence: PublicationEvidence,
    ) -> Result<PublicationEvidence, PublicationAdapterError> {
        let call = EstablishedPublicationCall::from_established(publication)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        // Keep exact-evidence validation and the caller-visible ACK in one
        // authority-shard critical section. A successor then either revokes
        // before this point or only after the evidence is bound to this exact
        // established publication.
        let result = self
            .local_authority
            .linearize_publication(&call, || {
                evidence.validate_for(&call).map_err(|_| ())?;
                Ok(evidence)
            })
            .map_err(|_| PublicationAdapterError::RecoveryRequired);
        if result.is_ok() {
            self.diagnostics
                .increment(DiagnosticsCounter::PublicationAcknowledged);
        }
        result
    }

    /// Invoke a provider operation with fail-closed local authority checks.
    ///
    /// After a provider future completes, the post-effect check intentionally
    /// runs even for an error, timeout, malformed reply, or `NotTransmitted`
    /// result. Dropping this outer future skips that check; effect-capable
    /// callers must therefore demote their capsule before their first await.
    /// Thus a takeover in flight never yields an ACK, restored begin retry, or
    /// external-effect permission under stale authority.
    async fn invoke_publication(
        &self,
        operation: PublicationOperation,
        publication: &EstablishedPublication,
    ) -> Result<PublicationProviderOutcome, PublicationAdapterError> {
        let call = EstablishedPublicationCall::from_established(publication)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        self.validate_before(&call).await?;

        self.diagnostics.increment(match operation {
            PublicationOperation::Status => DiagnosticsCounter::PublicationStatusCalls,
            PublicationOperation::Adopt => DiagnosticsCounter::PublicationAdoptCalls,
            PublicationOperation::Begin => DiagnosticsCounter::PublicationBeginCalls,
        });
        let _provider_in_flight = self.diagnostics.provider_in_flight();

        let response = tokio::time::timeout(PUBLICATION_EFFECT_DEADLINE, async {
            match operation {
                PublicationOperation::Status => self.provider.status(&call).await,
                PublicationOperation::Adopt => self.provider.adopt(&call).await,
                PublicationOperation::Begin => self.provider.begin_publication(&call).await,
            }
        })
        .await;
        drop(_provider_in_flight);

        // Do not move this barrier below result normalization.  Every outcome,
        // including a direct-begin NotTransmitted, is stale if the capability was
        // replaced or expired while the provider future was in flight.
        if self.validate_after(&call).await.is_err() {
            return Err(PublicationAdapterError::RecoveryRequired);
        }

        let outcome = match response {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => {
                return Err(PublicationAdapterError::RecoveryRequired);
            }
        };
        match outcome {
            PublicationProviderOutcome::Conflict => self
                .diagnostics
                .increment(DiagnosticsCounter::PublicationConflict),
            PublicationProviderOutcome::Published(_)
            | PublicationProviderOutcome::Absent
            | PublicationProviderOutcome::NotTransmitted
            | PublicationProviderOutcome::FreshNotTransmitted
            | PublicationProviderOutcome::OutcomeUnknown
            | PublicationProviderOutcome::Pending(_) => {}
        }
        // Every provider method receives the complete SDK-issued call, not
        // free-standing bytes: its stable ID is bound to the roster,
        // admission, terminal, receipt, and exact payload commitment.  The
        // provider reports a same-ID different-payload journal entry as
        // `Conflict`, which callers map to `PayloadConflict` above.
        Ok(outcome)
    }

    /// Invoke exactly one provider-owned compound fresh-publication operation
    /// between one pre-effect and one post-effect authority validation.
    async fn invoke_fresh_publication(
        &self,
        publication: &EstablishedPublication,
    ) -> Result<PublicationProviderOutcome, PublicationAdapterError> {
        let call = EstablishedPublicationCall::from_established(publication)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        self.validate_before(&call).await?;

        let _provider_in_flight = self.diagnostics.provider_in_flight();
        let response = tokio::time::timeout(PUBLICATION_EFFECT_DEADLINE, async {
            self.provider.publish_fresh_established(&call).await
        })
        .await;
        drop(_provider_in_flight);

        // Once the provider future completes, this postcheck applies to every
        // reply, including timeout, malformed reply, and direct
        // non-transmission. Dropping the outer future skips this code, so
        // `publish_fresh_established` demotes the capsule to StatusAdoptOnly
        // before its first await; cancellation can never restore fresh
        // authority under a successor.
        if self.validate_after(&call).await.is_err() {
            return Err(PublicationAdapterError::RecoveryRequired);
        }

        let outcome = match response {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => return Err(PublicationAdapterError::RecoveryRequired),
        };
        if matches!(outcome, PublicationProviderOutcome::Conflict) {
            self.diagnostics
                .increment(DiagnosticsCounter::PublicationConflict);
        }
        Ok(outcome)
    }

    /// Check the local revocation ledger, then a linearizable backend current
    /// authority read, then the local ledger again. The trailing local check
    /// closes a same-process successor installed while the remote read was in
    /// flight; a cross-process successor racing provider I/O is fenced by the
    /// provider's durable monotonic fence floor and caught by `validate_after`.
    async fn validate_before(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<(), PublicationAdapterError> {
        self.local_authority
            .permit_for_publication(call)
            .map_err(|_| PublicationAdapterError::AuthorityRejected)?;
        let current = CurrentPublicationAuthorityRead::from_publication_call(call)
            .map_err(|_| PublicationAdapterError::AuthorityRejected)?;
        self.authority_reader
            .read_current_publication_authority(current)
            .await
            .map_err(|_| PublicationAdapterError::AuthorityRejected)?;
        self.local_authority
            .permit_for_publication(call)
            .map(|_| ())
            .map_err(|_| PublicationAdapterError::AuthorityRejected)
    }

    /// Repeat the backend-current read and local validation after every
    /// provider operation. For a Published reply this read is the
    /// acknowledgement linearization point: failure is always ambiguous and
    /// cannot ACK.
    async fn validate_after(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<(), PublicationAdapterError> {
        let current = CurrentPublicationAuthorityRead::from_publication_call(call)
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        self.authority_reader
            .read_current_publication_authority(current)
            .await
            .map_err(|_| PublicationAdapterError::RecoveryRequired)?;
        self.local_authority
            .permit_for_publication(call)
            .map(|_| ())
            .map_err(|_| PublicationAdapterError::RecoveryRequired)
    }
}

#[derive(Clone, Copy)]
enum PublicationOperation {
    Status,
    Adopt,
    Begin,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fenced_mutation_roster::{
        canonical::{
            AdmissionProposal, EstablishedMutation, Member, MemberOperationId, MemberProvider,
            Profile, ProviderCallOutcome, RequestId, RosterId, Scope,
        },
        client::{
            AdmissionInput, AdmissionOutcome, CompleteProofSet, ExecuteOutcome,
            FencedMutationRosterClient, MemberOrdinal, MemberPrepareOutcome, RecoveryInput,
            RecoveryOutcome, TerminalReceipt, TerminalizationOutcome,
        },
        runtime::{
            AuthorityBinding, BackendRegistration, ConsensusCommitMetadata,
            CurrentPublicationAuthorityRead, FencedMutationRosterExecutorAttestor,
            PublicationAuthorityReader, RegistrationAdmissionProvenance, RegistrationDecision,
            RosterExecutor, RosterExecutorBackend, TerminalStatusDecision, TerminalizeDecision,
        },
    };
    use async_trait::async_trait;
    use opc_session_store::{
        fenced_mutation_roster::{
            RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
            RosterAttestationLeafCertificateV1, RosterAttestationTrustRootV1,
            RosterCompactAdmissionProvenanceSigningInputV2, RosterCompactAdmissionProvenanceV2,
            RosterIngressAttestationSigningInputV1, RosterIngressAttestationV1,
            RosterProviderOutcomeV1,
        },
        Clock, FenceToken, Generation, OwnerId, SessionConsensusClusterId,
        SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
        SessionConsensusIdentity, SessionKey, SessionKeyType, SessionLeaseManager,
        SqliteSessionBackend, StableId,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use std::{
        collections::BTreeMap,
        num::NonZeroUsize,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard,
        },
        time::Duration,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CallSnapshot {
        publication_id: [u8; 32],
        roster_id: RosterId,
        admission_commitment: [u8; 32],
        terminal_body_commitment: [u8; 32],
        receipt_commitment: [u8; 32],
        payload_commitment: [u8; 32],
        checkpoint: Vec<u8>,
        result: Vec<u8>,
        fence: FenceToken,
        lease_acquired_at: Timestamp,
        lease_expires_at: Timestamp,
    }

    impl CallSnapshot {
        fn capture(call: &EstablishedPublicationCall<'_>) -> Self {
            Self {
                publication_id: *call.publication_id().as_bytes(),
                roster_id: call.roster_id(),
                admission_commitment: call.admission_commitment(),
                terminal_body_commitment: call.terminal_body_commitment(),
                receipt_commitment: call.receipt_commitment(),
                payload_commitment: call.payload_commitment(),
                checkpoint: call.protected_checkpoint().to_vec(),
                result: call.protected_result().to_vec(),
                fence: call.current_fence(),
                lease_acquired_at: call.current_lease_acquired_at(),
                lease_expires_at: call.current_lease_expires_at(),
            }
        }
    }

    fn assert_same_durable_publication_body(expected: &CallSnapshot, actual: &CallSnapshot) {
        assert_eq!(expected.publication_id, actual.publication_id);
        assert_eq!(expected.roster_id, actual.roster_id);
        assert_eq!(expected.admission_commitment, actual.admission_commitment);
        assert_eq!(
            expected.terminal_body_commitment,
            actual.terminal_body_commitment
        );
        assert_eq!(expected.receipt_commitment, actual.receipt_commitment);
        assert_eq!(expected.payload_commitment, actual.payload_commitment);
        assert_eq!(expected.checkpoint, actual.checkpoint);
        assert_eq!(expected.result, actual.result);
    }

    fn same_durable_publication_body(expected: &CallSnapshot, actual: &CallSnapshot) -> bool {
        expected.publication_id == actual.publication_id
            && expected.roster_id == actual.roster_id
            && expected.admission_commitment == actual.admission_commitment
            && expected.terminal_body_commitment == actual.terminal_body_commitment
            && expected.receipt_commitment == actual.receipt_commitment
            && expected.payload_commitment == actual.payload_commitment
            && expected.checkpoint == actual.checkpoint
            && expected.result == actual.result
    }

    #[derive(Clone, Copy)]
    enum BeginReply {
        Pending,
        PendingThenPublished,
        Published,
        NotTransmittedThenPending,
    }

    #[derive(Clone, Copy)]
    enum StatusAfterAdopt {
        Published,
        Absent,
    }

    struct DurablePublicationProvider {
        begin_reply: BeginReply,
        status_after_adopt: StatusAfterAdopt,
        begin_calls: AtomicUsize,
        status_calls: AtomicUsize,
        adopt_calls: AtomicUsize,
        external_effects: AtomicUsize,
        snapshots: Mutex<Vec<CallSnapshot>>,
    }

    impl DurablePublicationProvider {
        fn ambiguous_then(status_after_adopt: StatusAfterAdopt) -> Self {
            Self {
                begin_reply: BeginReply::Pending,
                status_after_adopt,
                begin_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                adopt_calls: AtomicUsize::new(0),
                external_effects: AtomicUsize::new(0),
                snapshots: Mutex::new(Vec::new()),
            }
        }

        fn not_transmitted_then_published() -> Self {
            Self {
                begin_reply: BeginReply::NotTransmittedThenPending,
                status_after_adopt: StatusAfterAdopt::Published,
                begin_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                adopt_calls: AtomicUsize::new(0),
                external_effects: AtomicUsize::new(0),
                snapshots: Mutex::new(Vec::new()),
            }
        }

        fn begin_published() -> Self {
            Self {
                begin_reply: BeginReply::Published,
                status_after_adopt: StatusAfterAdopt::Published,
                begin_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                adopt_calls: AtomicUsize::new(0),
                external_effects: AtomicUsize::new(0),
                snapshots: Mutex::new(Vec::new()),
            }
        }

        fn pending_then_published() -> Self {
            Self {
                begin_reply: BeginReply::PendingThenPublished,
                status_after_adopt: StatusAfterAdopt::Published,
                begin_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
                adopt_calls: AtomicUsize::new(0),
                external_effects: AtomicUsize::new(0),
                snapshots: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, call: &EstablishedPublicationCall<'_>) {
            self.snapshots
                .lock()
                .expect("publication test provider lock")
                .push(CallSnapshot::capture(call));
        }

        fn snapshots(&self) -> Vec<CallSnapshot> {
            self.snapshots
                .lock()
                .expect("publication test provider lock")
                .clone()
        }

        fn evidence(call: &EstablishedPublicationCall<'_>) -> PublicationEvidence {
            PublicationEvidence::new(call, b"durable provider publication evidence".to_vec())
                .expect("bounded exact publication evidence")
        }
    }

    #[async_trait]
    impl EstablishedPublicationProvider for DurablePublicationProvider {
        type Error = ();

        async fn status(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            self.record(call);
            let call_number = self.status_calls.fetch_add(1, Ordering::SeqCst);
            if call_number == 0 {
                return Ok(PublicationProviderOutcome::Absent);
            }
            Ok(match self.status_after_adopt {
                StatusAfterAdopt::Published => {
                    PublicationProviderOutcome::Published(Self::evidence(call))
                }
                StatusAfterAdopt::Absent => PublicationProviderOutcome::Absent,
            })
        }

        async fn begin_publication(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            self.record(call);
            let call_number = self.begin_calls.fetch_add(1, Ordering::SeqCst);
            match self.begin_reply {
                BeginReply::Published => {
                    Ok(PublicationProviderOutcome::Published(Self::evidence(call)))
                }
                BeginReply::NotTransmittedThenPending if call_number == 0 => {
                    Ok(PublicationProviderOutcome::NotTransmitted)
                }
                BeginReply::Pending
                | BeginReply::PendingThenPublished
                | BeginReply::NotTransmittedThenPending => {
                    Ok(PublicationProviderOutcome::Pending(Self::evidence(call)))
                }
            }
        }

        async fn adopt(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            self.record(call);
            let call_number = self.adopt_calls.fetch_add(1, Ordering::SeqCst);
            if call_number == 0 {
                self.external_effects.fetch_add(1, Ordering::SeqCst);
            }
            Ok(match self.begin_reply {
                BeginReply::Pending | BeginReply::Published => {
                    PublicationProviderOutcome::OutcomeUnknown
                }
                BeginReply::PendingThenPublished | BeginReply::NotTransmittedThenPending => {
                    PublicationProviderOutcome::Published(Self::evidence(call))
                }
            })
        }
    }

    /// The only provider state retained across the restart proof below.  It is
    /// deliberately smaller than a provider object: one admitted exact intent,
    /// its externally-visible completion bit, and call counters/snapshots used
    /// to make the test's safety claims observable.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RestartPublicationState {
        Reserved,
        Attempted,
        Published,
    }

    #[derive(Clone, Copy)]
    enum FreshPublicationReply {
        Published,
        ReservedThenUnknown,
        /// The external effect crossed, but the provider crashed before it
        /// durably recorded completion evidence for that Attempted entry.
        EffectBeforeCompletionUnknown,
        EffectThenUnknown,
        NotTransmitted,
        LegacyNotTransmitted,
        Absent,
    }

    #[derive(Clone)]
    struct RestartPublicationIntent {
        snapshot: CallSnapshot,
        state: RestartPublicationState,
        /// The provider has crossed its one external effect boundary. This is
        /// intentionally distinct from a durable receipt/completion record:
        /// a crash between them must never authorize a replay.
        effect_crossed: bool,
        completion_evidence_durable: bool,
    }

    #[derive(Default)]
    struct RestartPublicationJournalState {
        /// Production journals are keyed by the immutable publication ID, not
        /// by a process-global singleton. Each key independently retains its
        /// exact body and monotonic fence floor.
        intents: BTreeMap<[u8; 32], RestartPublicationIntent>,
        fence_floors: BTreeMap<[u8; 32], FenceToken>,
    }

    #[derive(Default)]
    struct RestartPublicationJournal {
        state: Mutex<RestartPublicationJournalState>,
        provider_authority_expired: AtomicBool,
        status_calls: AtomicUsize,
        begin_calls: AtomicUsize,
        adopt_calls: AtomicUsize,
        fresh_calls: AtomicUsize,
        external_effects: AtomicUsize,
        snapshots: Mutex<Vec<CallSnapshot>>,
    }

    impl RestartPublicationJournal {
        fn authorize<'a>(
            &'a self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<(CallSnapshot, MutexGuard<'a, RestartPublicationJournalState>), ()> {
            if self.provider_authority_expired.load(Ordering::SeqCst)
                || call.current_lease_expires_at() <= call.current_lease_acquired_at()
            {
                return Err(());
            }
            let snapshot = CallSnapshot::capture(call);
            let mut state = self
                .state
                .lock()
                .expect("restart publication journal state lock");
            if state
                .fence_floors
                .get(&snapshot.publication_id)
                .is_some_and(|floor| call.current_fence() < *floor)
            {
                return Err(());
            }
            state
                .fence_floors
                .insert(snapshot.publication_id, call.current_fence());
            self.snapshots
                .lock()
                .expect("restart publication journal snapshots lock")
                .push(snapshot.clone());
            Ok((snapshot, state))
        }

        fn admit_intent(
            state: &mut RestartPublicationJournalState,
            snapshot: CallSnapshot,
        ) -> Result<RestartPublicationState, ()> {
            match state.intents.get(&snapshot.publication_id) {
                Some(retained) => {
                    if !same_durable_publication_body(&retained.snapshot, &snapshot) {
                        return Err(());
                    }
                    Ok(retained.state)
                }
                None => {
                    state.intents.insert(
                        snapshot.publication_id,
                        RestartPublicationIntent {
                            snapshot,
                            state: RestartPublicationState::Reserved,
                            effect_crossed: false,
                            completion_evidence_durable: false,
                        },
                    );
                    Ok(RestartPublicationState::Reserved)
                }
            }
        }

        fn only_intent(&self) -> RestartPublicationIntent {
            let state = self
                .state
                .lock()
                .expect("restart publication journal state lock");
            assert_eq!(
                state.intents.len(),
                1,
                "single-publication test must observe exactly one journal identity"
            );
            state
                .intents
                .values()
                .next()
                .expect("one retained publication intent")
                .clone()
        }

        fn intent(&self) -> CallSnapshot {
            self.only_intent().snapshot
        }

        fn state(&self) -> RestartPublicationState {
            self.only_intent().state
        }

        fn effect_crossed(&self) -> bool {
            self.only_intent().effect_crossed
        }

        fn completion_evidence_durable(&self) -> bool {
            self.only_intent().completion_evidence_durable
        }

        fn fence_floor(&self) -> FenceToken {
            let state = self
                .state
                .lock()
                .expect("restart publication journal state lock");
            assert_eq!(
                state.fence_floors.len(),
                1,
                "single-publication test must observe one durable fence floor"
            );
            *state
                .fence_floors
                .values()
                .next()
                .expect("an authorized provider call raises a durable fence floor")
        }

        fn intent_count(&self) -> usize {
            self.state
                .lock()
                .expect("restart publication journal state lock")
                .intents
                .len()
        }

        fn reserve_for_test(&self, snapshot: CallSnapshot) -> Result<(), ()> {
            let mut state = self
                .state
                .lock()
                .expect("restart publication journal state lock");
            Self::admit_intent(&mut state, snapshot).map(|_| ())
        }

        fn expire_provider_authority(&self) {
            self.provider_authority_expired
                .store(true, Ordering::SeqCst);
        }

        fn snapshots(&self) -> Vec<CallSnapshot> {
            self.snapshots
                .lock()
                .expect("restart publication journal snapshots lock")
                .clone()
        }
    }

    /// A process-local provider façade. Reconstructing it from the journal is
    /// the test's simulated provider process restart; it has no retained
    /// adapter, executor, authority-registry, or provider-object state.
    struct RestartJournalProvider {
        journal: Arc<RestartPublicationJournal>,
        lose_first_adopt_reply: bool,
        fresh_reply: FreshPublicationReply,
    }

    impl RestartJournalProvider {
        fn initial(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                lose_first_adopt_reply: true,
                fresh_reply: FreshPublicationReply::Published,
            }
        }

        fn recover(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                lose_first_adopt_reply: false,
                fresh_reply: FreshPublicationReply::Published,
            }
        }

        fn fresh(journal: Arc<RestartPublicationJournal>, reply: FreshPublicationReply) -> Self {
            Self {
                journal,
                lose_first_adopt_reply: false,
                fresh_reply: reply,
            }
        }
    }

    #[async_trait]
    impl EstablishedPublicationProvider for RestartJournalProvider {
        type Error = ();

        async fn publish_fresh_established(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, mut state) = self.journal.authorize(call)?;
            self.journal.fresh_calls.fetch_add(1, Ordering::SeqCst);
            let publication_id = snapshot.publication_id;

            match state.intents.get(&publication_id) {
                Some(retained) if !same_durable_publication_body(&retained.snapshot, &snapshot) => {
                    return Ok(PublicationProviderOutcome::Conflict)
                }
                Some(_) => {}
                None if matches!(self.fresh_reply, FreshPublicationReply::NotTransmitted) => {
                    return Ok(PublicationProviderOutcome::FreshNotTransmitted)
                }
                None if matches!(
                    self.fresh_reply,
                    FreshPublicationReply::LegacyNotTransmitted
                ) =>
                {
                    return Ok(PublicationProviderOutcome::NotTransmitted)
                }
                None if matches!(self.fresh_reply, FreshPublicationReply::Absent) => {
                    return Ok(PublicationProviderOutcome::Absent)
                }
                None => {
                    // The immutable identity is durable before any attempt or
                    // effect. This assignment models the journal's Reserved
                    // transaction boundary.
                    state.intents.insert(
                        publication_id,
                        RestartPublicationIntent {
                            snapshot,
                            state: RestartPublicationState::Reserved,
                            effect_crossed: false,
                            completion_evidence_durable: false,
                        },
                    );
                }
            }

            let intent = state
                .intents
                .get_mut(&publication_id)
                .expect("fresh publication retained one exact journal identity");
            match intent.state {
                RestartPublicationState::Published => Ok(PublicationProviderOutcome::Published(
                    DurablePublicationProvider::evidence(call),
                )),
                // No provider-local transport proof permits an Attempted
                // journal to replay an effect. A successor can only observe
                // it and wait for a conclusive receipt.
                RestartPublicationState::Attempted => {
                    if intent.completion_evidence_durable {
                        intent.state = RestartPublicationState::Published;
                        Ok(PublicationProviderOutcome::Published(
                            DurablePublicationProvider::evidence(call),
                        ))
                    } else {
                        Ok(PublicationProviderOutcome::Pending(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                }
                RestartPublicationState::Reserved => {
                    if matches!(self.fresh_reply, FreshPublicationReply::ReservedThenUnknown) {
                        return Ok(PublicationProviderOutcome::OutcomeUnknown);
                    }

                    // This marker is durable before the sole external effect.
                    intent.state = RestartPublicationState::Attempted;
                    self.journal.external_effects.fetch_add(1, Ordering::SeqCst);
                    intent.effect_crossed = true;
                    if matches!(
                        self.fresh_reply,
                        FreshPublicationReply::EffectBeforeCompletionUnknown
                    ) {
                        return Ok(PublicationProviderOutcome::OutcomeUnknown);
                    }
                    intent.completion_evidence_durable = true;
                    if matches!(self.fresh_reply, FreshPublicationReply::EffectThenUnknown) {
                        return Ok(PublicationProviderOutcome::OutcomeUnknown);
                    }

                    intent.state = RestartPublicationState::Published;
                    Ok(PublicationProviderOutcome::Published(
                        DurablePublicationProvider::evidence(call),
                    ))
                }
            }
        }

        async fn status(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, state) = self.journal.authorize(call)?;
            self.journal.status_calls.fetch_add(1, Ordering::SeqCst);
            Ok(match state.intents.get(&snapshot.publication_id) {
                None => PublicationProviderOutcome::Absent,
                Some(retained) if !same_durable_publication_body(&retained.snapshot, &snapshot) => {
                    PublicationProviderOutcome::Conflict
                }
                Some(retained) => match retained.state {
                    RestartPublicationState::Published => PublicationProviderOutcome::Published(
                        DurablePublicationProvider::evidence(call),
                    ),
                    RestartPublicationState::Reserved | RestartPublicationState::Attempted => {
                        PublicationProviderOutcome::Pending(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                },
            })
        }

        async fn begin_publication(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, mut state) = self.journal.authorize(call)?;
            self.journal.begin_calls.fetch_add(1, Ordering::SeqCst);
            Ok(
                match RestartPublicationJournal::admit_intent(&mut state, snapshot) {
                    Err(()) => PublicationProviderOutcome::Conflict,
                    Ok(RestartPublicationState::Reserved | RestartPublicationState::Attempted) => {
                        PublicationProviderOutcome::Pending(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                    Ok(RestartPublicationState::Published) => {
                        PublicationProviderOutcome::Published(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                },
            )
        }

        async fn adopt(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, mut journal_state) = self.journal.authorize(call)?;
            self.journal.adopt_calls.fetch_add(1, Ordering::SeqCst);
            let Some(intent) = journal_state.intents.get_mut(&snapshot.publication_id) else {
                return Ok(PublicationProviderOutcome::Absent);
            };
            if !same_durable_publication_body(&intent.snapshot, &snapshot) {
                return Ok(PublicationProviderOutcome::Conflict);
            }
            match intent.state {
                RestartPublicationState::Published => Ok(PublicationProviderOutcome::Published(
                    DurablePublicationProvider::evidence(call),
                )),
                RestartPublicationState::Attempted => {
                    if !intent.completion_evidence_durable {
                        return Ok(PublicationProviderOutcome::Pending(
                            DurablePublicationProvider::evidence(call),
                        ));
                    }
                    intent.state = RestartPublicationState::Published;
                    Ok(PublicationProviderOutcome::Published(
                        DurablePublicationProvider::evidence(call),
                    ))
                }
                RestartPublicationState::Reserved => {
                    // The attempt marker becomes durable before the one
                    // external effect. A successor can reconcile this state,
                    // but it can never infer resend authority from it.
                    intent.state = RestartPublicationState::Attempted;
                    self.journal.external_effects.fetch_add(1, Ordering::SeqCst);
                    intent.effect_crossed = true;
                    intent.completion_evidence_durable = true;
                    if self.lose_first_adopt_reply {
                        Ok(PublicationProviderOutcome::OutcomeUnknown)
                    } else {
                        intent.state = RestartPublicationState::Published;
                        Ok(PublicationProviderOutcome::Published(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum FreshGatePoint {
        /// Pause after durable `Attempted` and before the external effect.
        BeforeEffect,
        /// Pause after the external effect and durable completion evidence,
        /// but before the provider reply reaches the SDK postcheck.
        AfterEffect,
    }

    /// A compound provider whose first fresh call pauses at an explicit
    /// effect boundary. This makes cancellation and post-effect takeover
    /// cuts deterministic without inventing a second publication identity.
    struct GatedFreshJournalProvider {
        journal: Arc<RestartPublicationJournal>,
        gate_point: FreshGatePoint,
        reached_gate: tokio::sync::Notify,
        resume: tokio::sync::Notify,
    }

    impl GatedFreshJournalProvider {
        fn new(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                gate_point: FreshGatePoint::BeforeEffect,
                reached_gate: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            }
        }

        fn after_effect(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                gate_point: FreshGatePoint::AfterEffect,
                reached_gate: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
            }
        }

        async fn wait_for_attempt(&self) {
            self.reached_gate.notified().await;
        }

        async fn wait_for_effect(&self) {
            self.reached_gate.notified().await;
        }

        fn resume(&self) {
            self.resume.notify_one();
        }
    }

    #[async_trait]
    impl EstablishedPublicationProvider for GatedFreshJournalProvider {
        type Error = ();

        async fn publish_fresh_established(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let publication_id = *call.publication_id().as_bytes();
            {
                let (snapshot, mut state) = self.journal.authorize(call)?;
                self.journal.fresh_calls.fetch_add(1, Ordering::SeqCst);
                match state.intents.get(&publication_id) {
                    Some(retained)
                        if !same_durable_publication_body(&retained.snapshot, &snapshot) =>
                    {
                        return Ok(PublicationProviderOutcome::Conflict)
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Published,
                        ..
                    }) => {
                        return Ok(PublicationProviderOutcome::Published(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Attempted,
                        ..
                    }) => {
                        return Ok(PublicationProviderOutcome::Pending(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Reserved,
                        ..
                    }) => {}
                    None => {
                        state.intents.insert(
                            publication_id,
                            RestartPublicationIntent {
                                snapshot,
                                state: RestartPublicationState::Reserved,
                                effect_crossed: false,
                                completion_evidence_durable: false,
                            },
                        );
                    }
                }
                let intent = state
                    .intents
                    .get_mut(&publication_id)
                    .expect("compound publication retained one exact identity");
                intent.state = RestartPublicationState::Attempted;
            }

            if matches!(self.gate_point, FreshGatePoint::BeforeEffect) {
                self.reached_gate.notify_one();
                self.resume.notified().await;
            }

            let gate_after_effect = matches!(self.gate_point, FreshGatePoint::AfterEffect);
            {
                let (snapshot, mut state) = self.journal.authorize(call)?;
                let Some(intent) = state.intents.get_mut(&publication_id) else {
                    return Ok(PublicationProviderOutcome::Absent);
                };
                if !same_durable_publication_body(&intent.snapshot, &snapshot)
                    || intent.state != RestartPublicationState::Attempted
                    || intent.effect_crossed
                {
                    return Ok(PublicationProviderOutcome::Pending(
                        DurablePublicationProvider::evidence(call),
                    ));
                }
                self.journal.external_effects.fetch_add(1, Ordering::SeqCst);
                intent.effect_crossed = true;
                intent.completion_evidence_durable = true;
                if !gate_after_effect {
                    intent.state = RestartPublicationState::Published;
                }
            }

            if gate_after_effect {
                self.reached_gate.notify_one();
                self.resume.notified().await;
                let mut state = self
                    .journal
                    .state
                    .lock()
                    .expect("restart publication journal state lock");
                if let Some(intent) = state.intents.get_mut(&publication_id) {
                    if intent.state == RestartPublicationState::Attempted && intent.effect_crossed {
                        intent.state = RestartPublicationState::Published;
                    }
                }
            }
            Ok(PublicationProviderOutcome::Published(
                DurablePublicationProvider::evidence(call),
            ))
        }

        async fn status(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .status(call)
                .await
        }

        async fn begin_publication(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .begin_publication(call)
                .await
        }

        async fn adopt(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .adopt(call)
                .await
        }
    }

    /// A deterministic two-caller compound provider.  The barriers force both
    /// invocations to observe the same durable `Reserved` entry, then the same
    /// `Attempted` entry, before either may cross the one external effect.
    /// This is deliberately not a mutex-only test: both futures must suspend
    /// at each journal boundary for the assertion to prove duplicate safety.
    struct ConcurrentFreshJournalProvider {
        journal: Arc<RestartPublicationJournal>,
        reserved_barrier: tokio::sync::Barrier,
        attempted_barrier: tokio::sync::Barrier,
        observer_ready_barrier: tokio::sync::Barrier,
        effect_complete: tokio::sync::Notify,
    }

    impl ConcurrentFreshJournalProvider {
        fn new(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                reserved_barrier: tokio::sync::Barrier::new(2),
                attempted_barrier: tokio::sync::Barrier::new(2),
                observer_ready_barrier: tokio::sync::Barrier::new(2),
                effect_complete: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait]
    impl EstablishedPublicationProvider for ConcurrentFreshJournalProvider {
        type Error = ();

        async fn publish_fresh_established(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let publication_id = *call.publication_id().as_bytes();
            {
                let (snapshot, mut state) = self.journal.authorize(call)?;
                self.journal.fresh_calls.fetch_add(1, Ordering::SeqCst);
                match state.intents.get(&publication_id) {
                    Some(retained)
                        if !same_durable_publication_body(&retained.snapshot, &snapshot) =>
                    {
                        return Ok(PublicationProviderOutcome::Conflict)
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Published,
                        ..
                    }) => {
                        return Ok(PublicationProviderOutcome::Published(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Attempted,
                        ..
                    }) => {
                        return Ok(PublicationProviderOutcome::Pending(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                    Some(RestartPublicationIntent {
                        state: RestartPublicationState::Reserved,
                        ..
                    }) => {}
                    None => {
                        state.intents.insert(
                            publication_id,
                            RestartPublicationIntent {
                                snapshot,
                                state: RestartPublicationState::Reserved,
                                effect_crossed: false,
                                completion_evidence_durable: false,
                            },
                        );
                    }
                }
            }

            // Both calls suspend after seeing `Reserved`.  A sequential fake
            // would never reach this barrier from its first provider future.
            self.reserved_barrier.wait().await;

            let owns_effect = {
                let (snapshot, mut state) = self.journal.authorize(call)?;
                let intent = state
                    .intents
                    .get_mut(&publication_id)
                    .expect("concurrent fresh calls retain one exact identity");
                if !same_durable_publication_body(&intent.snapshot, &snapshot) {
                    return Ok(PublicationProviderOutcome::Conflict);
                }
                match intent.state {
                    RestartPublicationState::Reserved => {
                        // This durable marker is the handoff boundary: exactly
                        // one interleaved caller receives effect ownership.
                        intent.state = RestartPublicationState::Attempted;
                        true
                    }
                    RestartPublicationState::Attempted => false,
                    RestartPublicationState::Published => {
                        return Ok(PublicationProviderOutcome::Published(
                            DurablePublicationProvider::evidence(call),
                        ))
                    }
                }
            };

            // Both calls suspend after observing `Attempted`, before the owner
            // is permitted to cross the effect.  This excludes a falsely
            // serialized mutex-only duplicate test.
            self.attempted_barrier.wait().await;
            self.observer_ready_barrier.wait().await;

            if owns_effect {
                let (snapshot, mut state) = self.journal.authorize(call)?;
                let intent = state
                    .intents
                    .get_mut(&publication_id)
                    .expect("the attempted identity remains retained");
                assert!(same_durable_publication_body(&intent.snapshot, &snapshot));
                assert!(matches!(intent.state, RestartPublicationState::Attempted));
                assert!(!intent.effect_crossed);
                self.journal.external_effects.fetch_add(1, Ordering::SeqCst);
                intent.effect_crossed = true;
                intent.completion_evidence_durable = true;
                intent.state = RestartPublicationState::Published;
                // `notify_one` retains a permit if the observer has not yet
                // registered its wait after the preceding synchronization.
                self.effect_complete.notify_one();
            } else {
                self.effect_complete.notified().await;
                assert!(matches!(
                    self.journal.state(),
                    RestartPublicationState::Published
                ));
            }

            Ok(PublicationProviderOutcome::Published(
                DurablePublicationProvider::evidence(call),
            ))
        }

        async fn status(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .status(call)
                .await
        }

        async fn begin_publication(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .begin_publication(call)
                .await
        }

        async fn adopt(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            RestartJournalProvider::recover(Arc::clone(&self.journal))
                .adopt(call)
                .await
        }
    }

    /// Shared provider journal that pauses precisely before its first intent
    /// admission. The test drives a successor through the same journal while
    /// the old call is paused, proving that the provider's durable fence floor
    /// rejects the delayed lower-fence call and that the old adapter's post
    /// read cannot acknowledge it.
    struct GatedRestartJournalProvider {
        journal: Arc<RestartPublicationJournal>,
        gate_next_begin: AtomicBool,
        begin_started: tokio::sync::Notify,
        resume_begin: tokio::sync::Notify,
    }

    impl GatedRestartJournalProvider {
        fn new(journal: Arc<RestartPublicationJournal>) -> Self {
            Self {
                journal,
                gate_next_begin: AtomicBool::new(true),
                begin_started: tokio::sync::Notify::new(),
                resume_begin: tokio::sync::Notify::new(),
            }
        }

        async fn wait_for_first_begin(&self) {
            self.begin_started.notified().await;
        }

        fn resume_first_begin(&self) {
            self.resume_begin.notify_one();
        }
    }

    #[async_trait]
    impl EstablishedPublicationProvider for GatedRestartJournalProvider {
        type Error = ();

        async fn status(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, state) = self.journal.authorize(call)?;
            self.journal.status_calls.fetch_add(1, Ordering::SeqCst);
            Ok(match state.intents.get(&snapshot.publication_id) {
                None => PublicationProviderOutcome::Absent,
                Some(retained) if !same_durable_publication_body(&retained.snapshot, &snapshot) => {
                    PublicationProviderOutcome::Conflict
                }
                Some(retained) => match retained.state {
                    RestartPublicationState::Published => PublicationProviderOutcome::Published(
                        DurablePublicationProvider::evidence(call),
                    ),
                    RestartPublicationState::Reserved | RestartPublicationState::Attempted => {
                        PublicationProviderOutcome::Pending(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                },
            })
        }

        async fn begin_publication(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            if self.gate_next_begin.swap(false, Ordering::SeqCst) {
                self.begin_started.notify_one();
                self.resume_begin.notified().await;
            }
            let (snapshot, mut state) = self.journal.authorize(call)?;
            self.journal.begin_calls.fetch_add(1, Ordering::SeqCst);
            Ok(
                match RestartPublicationJournal::admit_intent(&mut state, snapshot) {
                    Err(()) => PublicationProviderOutcome::Conflict,
                    Ok(RestartPublicationState::Reserved | RestartPublicationState::Attempted) => {
                        PublicationProviderOutcome::Pending(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                    Ok(RestartPublicationState::Published) => {
                        PublicationProviderOutcome::Published(DurablePublicationProvider::evidence(
                            call,
                        ))
                    }
                },
            )
        }

        async fn adopt(
            &self,
            call: &EstablishedPublicationCall<'_>,
        ) -> Result<PublicationProviderOutcome, Self::Error> {
            let (snapshot, mut state) = self.journal.authorize(call)?;
            self.journal.adopt_calls.fetch_add(1, Ordering::SeqCst);
            let Some(intent) = state.intents.get_mut(&snapshot.publication_id) else {
                return Ok(PublicationProviderOutcome::Absent);
            };
            if !same_durable_publication_body(&intent.snapshot, &snapshot) {
                return Ok(PublicationProviderOutcome::Conflict);
            }
            match intent.state {
                RestartPublicationState::Published => Ok(PublicationProviderOutcome::Published(
                    DurablePublicationProvider::evidence(call),
                )),
                RestartPublicationState::Reserved | RestartPublicationState::Attempted => {
                    intent.state = RestartPublicationState::Attempted;
                    self.journal.external_effects.fetch_add(1, Ordering::SeqCst);
                    intent.effect_crossed = true;
                    intent.completion_evidence_durable = true;
                    intent.state = RestartPublicationState::Published;
                    Ok(PublicationProviderOutcome::Published(
                        DurablePublicationProvider::evidence(call),
                    ))
                }
            }
        }
    }

    /// Test-only protected Provider leaf. Its certificate chains to the same
    /// root/configuration/scope as `TestAttestor`, while every receipt is
    /// signed over the exact SDK-issued call challenge and proof epoch.
    struct TestProviderReceiptIssuer {
        certificate: RosterAttestationLeafCertificatePartsV1,
        key: SigningKey,
    }

    impl TestProviderReceiptIssuer {
        fn new(scope: Scope) -> Self {
            let root_key =
                SigningKey::from_bytes((&[0x31; 32]).into()).expect("fixed test root scalar");
            let key =
                SigningKey::from_bytes((&[0x33; 32]).into()).expect("fixed test provider scalar");
            let root = RosterAttestationTrustRootV1::new(
                [0xa1; 32],
                root_key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .expect("compressed root key width"),
            )
            .expect("test root");
            let now = Timestamp::now_utc();
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: root.root_id(),
                role: RosterAttestationCertificateRoleV1::Provider,
                configuration_identity: SessionConsensusIdentity::new(
                    SessionConsensusClusterId::from_bytes([0x41; 32]),
                    SessionConsensusConfigurationId::from_bytes([0x42; 32]),
                    SessionConsensusConfigurationEpoch::new(1).expect("nonzero test epoch"),
                ),
                scope: scope.digest(),
                subject_identity_commitment: [0x44; 32],
                leaf_epoch: 1,
                key_id: [0x45; 32],
                not_before: now.add_seconds(-60).expect("test certificate start"),
                not_after: now.add_seconds(3_600).expect("test certificate expiry"),
                public_key: key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .expect("compressed provider key width"),
                root_signature: [0; 64],
            };
            certificate.root_signature = TestAttestor::sign(
                &root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                    .expect("test provider certificate digest"),
            );
            Self { certificate, key }
        }

        fn applied_executed(
            &self,
            call: &super::super::canonical::MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, ()> {
            let evidence = vec![call.ordinal().saturating_add(1)];
            let outcome = RosterProviderOutcomeV1::AppliedExecuted;
            if call.provider_proof_epoch() == 0 {
                return Err(());
            }
            let challenge = call.provider_receipt_challenge();
            let digest = challenge
                .protected_provider_leaf_receipt_digest(
                    self.certificate.subject_identity_commitment,
                    outcome,
                    &evidence,
                )
                .map_err(|_| ())?;
            let capsule = challenge
                .protected_provider_leaf_signed_capsule(
                    outcome,
                    evidence,
                    self.certificate.clone(),
                    TestAttestor::sign(&self.key, digest),
                )
                .map_err(|_| ())?;
            Ok(ProviderCallOutcome::conclusive_receipt(capsule))
        }
    }

    struct ConclusiveMemberProvider {
        receipts: TestProviderReceiptIssuer,
    }

    impl ConclusiveMemberProvider {
        fn new(scope: Scope) -> Self {
            Self {
                receipts: TestProviderReceiptIssuer::new(scope),
            }
        }
    }

    #[async_trait]
    impl MemberProvider for ConclusiveMemberProvider {
        type Error = ();

        async fn prepare(
            &self,
            _call: &super::super::canonical::MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            Ok(ProviderCallOutcome::prepared_not_run())
        }

        async fn execute(
            &self,
            call: &super::super::canonical::MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            self.receipts.applied_executed(call)
        }

        async fn status(
            &self,
            _call: &super::super::canonical::MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            Ok(ProviderCallOutcome::not_found())
        }

        async fn adopt(
            &self,
            _call: &super::super::canonical::MemberCall<'_>,
        ) -> Result<ProviderCallOutcome, Self::Error> {
            Ok(ProviderCallOutcome::not_found())
        }
    }

    #[derive(Default)]
    struct CountingBackend {
        registrations: AtomicUsize,
        terminalizations: AtomicUsize,
        authority_reads: AtomicUsize,
        authority_read_expired: AtomicBool,
        current_authority: Mutex<Option<AuthorityBinding>>,
        committed: Mutex<Option<super::super::runtime::CommittedTerminal>>,
        recovery: Mutex<Option<(BackendRegistration, Arc<super::super::canonical::Admission>)>>,
    }

    impl CountingBackend {
        fn authority_reads(&self) -> usize {
            self.authority_reads.load(Ordering::SeqCst)
        }

        fn expire_current_authority_for_read(&self) {
            self.authority_read_expired.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl RosterExecutorBackend for CountingBackend {
        type Error = ();

        fn expected_roster_attestation_trust_root_identity(
            &self,
        ) -> Option<opc_session_store::fenced_mutation_roster::RosterAttestationTrustRootIdentityV1>
        {
            let root_key =
                SigningKey::from_bytes((&[0x31; 32]).into()).expect("fixed test root scalar");
            Some(
                RosterAttestationTrustRootV1::new(
                    [0xa1; 32],
                    root_key
                        .verifying_key()
                        .to_sec1_point(true)
                        .as_bytes()
                        .try_into()
                        .expect("compressed root key width"),
                )
                .expect("test root")
                .identity(),
            )
        }

        fn current_roster_configuration_identity(&self) -> Option<SessionConsensusIdentity> {
            Some(SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([0x41; 32]),
                SessionConsensusConfigurationId::from_bytes([0x42; 32]),
                SessionConsensusConfigurationEpoch::new(1).expect("nonzero test epoch"),
            ))
        }

        async fn register(
            &self,
            request: &super::super::runtime::RegistrationRequest,
        ) -> Result<RegistrationDecision, Self::Error> {
            self.registrations.fetch_add(1, Ordering::SeqCst);
            let registration = BackendRegistration::issue(
                [0x91; 32],
                RequestId::bind(1, request.admission()).expect("bound registration request"),
                request.admission(),
            )
            .expect("valid backend registration");
            *self
                .current_authority
                .lock()
                .expect("current authority lock") = Some(request.authority().clone());
            Ok(RegistrationDecision::FreshlyAdmittedWithProvenance(
                registration,
                RegistrationAdmissionProvenance::V1(test_compact_admission_provenance(
                    request.admission(),
                    request.authority(),
                )),
            ))
        }

        async fn admission_status(
            &self,
            _request: super::super::runtime::AdmissionStatusRequest<'_>,
        ) -> Result<RegistrationDecision, Self::Error> {
            unreachable!("fixture never loses the admission reply")
        }

        async fn recover(
            &self,
            request: &super::super::runtime::RecoveryRequest,
        ) -> Result<RegistrationDecision, Self::Error> {
            let (registration, admission) = self
                .recovery
                .lock()
                .expect("recovery test record lock")
                .clone()
                .expect("fixture persists the exact terminal before recovery");
            if request.lookup().scope() != request.authority().ingress_scope()
                || request.lookup().roster_id() != admission.roster_id()
                || request.authority().fence().get() <= admission.admission_fence().get()
            {
                return Err(());
            }
            let mut current = self
                .current_authority
                .lock()
                .expect("current authority lock");
            if current.as_ref().is_some_and(|existing| {
                request.authority().fence() < existing.fence()
                    || (request.authority().fence() == existing.fence()
                        && request.authority() != existing)
            }) {
                return Err(());
            }
            // The test fixture models a successor lease already acquired in
            // the shared durable backend before this read-only recovery. This
            // updates only the fake's observable authority snapshot; neither
            // roster mutation counter changes.
            *current = Some(
                AuthorityBinding::for_successor(&admission, request.authority()).map_err(|_| ())?,
            );
            drop(current);
            let committed = self
                .committed
                .lock()
                .expect("terminal test record lock")
                .clone()
                .expect("fixture terminal is committed before recovery");
            Ok(RegistrationDecision::Terminal {
                registration,
                admission,
                committed: Box::new(committed),
            })
        }

        async fn terminal_status(
            &self,
            _request: super::super::runtime::TerminalStatusRequest<'_>,
        ) -> Result<TerminalStatusDecision, Self::Error> {
            Ok(TerminalStatusDecision::Recorded(Box::new(
                self.committed
                    .lock()
                    .expect("terminal test record lock")
                    .clone()
                    .expect("fixture terminal is committed before status"),
            )))
        }

        async fn terminalize(
            &self,
            request: super::super::runtime::TerminalizeRequest<'_>,
        ) -> Result<TerminalizeDecision, Self::Error> {
            self.terminalizations.fetch_add(1, Ordering::SeqCst);
            let committed = super::super::runtime::CommittedTerminal::issue(
                request.registration(),
                request.admission(),
                request.authority(),
                request.body(),
                ConsensusCommitMetadata::issue(1, 1, Timestamp::now_utc())
                    .expect("current terminal commit metadata"),
            )
            .expect("durable terminal must bind the exact prepared body");
            *self.committed.lock().expect("terminal test record lock") = Some(committed.clone());
            *self.recovery.lock().expect("recovery test record lock") = Some((
                request.registration(),
                Arc::new(request.admission().clone()),
            ));
            Ok(TerminalizeDecision::Terminalized(committed))
        }
    }

    #[async_trait]
    impl PublicationAuthorityReader for CountingBackend {
        type Error = ();

        async fn read_current_publication_authority(
            &self,
            request: CurrentPublicationAuthorityRead<'_>,
        ) -> Result<(), Self::Error> {
            self.authority_reads.fetch_add(1, Ordering::SeqCst);
            let (registration, admission) = self
                .recovery
                .lock()
                .expect("recovery test record lock")
                .clone()
                .ok_or(())?;
            let committed = self
                .committed
                .lock()
                .expect("terminal test record lock")
                .clone()
                .ok_or(())?;
            let current = self
                .current_authority
                .lock()
                .expect("current authority lock")
                .clone()
                .ok_or(())?;
            if request.roster_id() != admission.roster_id()
                || request.admission_commitment() != admission.body_commitment()
                || request.terminal_body_commitment() != committed.record().body_commitment()
                || request.receipt_commitment() != committed.receipt_commitment()
                || request.logical_owner() != admission.logical_owner()
                || request.admission_fence() != admission.admission_fence()
            {
                return Err(());
            }
            let now = if self.authority_read_expired.load(Ordering::SeqCst) {
                current.expires_at()
            } else {
                Timestamp::now_utc()
            };
            request
                .validate_backend_current(registration, &current, now)
                .map_err(|_| ())
        }
    }

    #[derive(Debug)]
    struct TestClock {
        expired: AtomicBool,
    }

    impl TestClock {
        fn expire(&self) {
            self.expired.store(true, Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_utc(&self) -> Timestamp {
            let now = Timestamp::now_utc();
            if self.expired.load(Ordering::SeqCst) {
                now.add_seconds(120)
                    .expect("test time remains representable")
            } else {
                now
            }
        }
    }

    struct TestAttestor {
        root: RosterAttestationTrustRootV1,
        certificate: RosterAttestationLeafCertificatePartsV1,
        key: SigningKey,
    }

    impl TestAttestor {
        fn new(scope: Scope) -> Self {
            let root_key =
                SigningKey::from_bytes((&[0x31; 32]).into()).expect("fixed test root scalar");
            let key =
                SigningKey::from_bytes((&[0x32; 32]).into()).expect("fixed test executor scalar");
            let root = RosterAttestationTrustRootV1::new(
                [0xa1; 32],
                root_key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .expect("compressed root key width"),
            )
            .expect("test root");
            let now = Timestamp::now_utc();
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: root.root_id(),
                role: RosterAttestationCertificateRoleV1::Executor,
                configuration_identity: SessionConsensusIdentity::new(
                    SessionConsensusClusterId::from_bytes([0x41; 32]),
                    SessionConsensusConfigurationId::from_bytes([0x42; 32]),
                    SessionConsensusConfigurationEpoch::new(1).expect("nonzero test epoch"),
                ),
                scope: scope.digest(),
                subject_identity_commitment: [0x42; 32],
                leaf_epoch: 1,
                key_id: [0x43; 32],
                not_before: now.add_seconds(-60).expect("test certificate start"),
                not_after: now.add_seconds(3_600).expect("test certificate expiry"),
                public_key: key
                    .verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .expect("compressed executor key width"),
                root_signature: [0; 64],
            };
            certificate.root_signature = Self::sign(
                &root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                    .expect("test certificate digest"),
            );
            Self {
                root,
                certificate,
                key,
            }
        }

        fn sign(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
            let signature: p256::ecdsa::Signature = key
                .sign_prehash(&digest)
                .expect("fixed test prehash signature");
            signature.normalize_s().to_bytes().into()
        }
    }

    fn test_compact_admission_provenance(
        admission: &super::super::canonical::Admission,
        authority: &super::super::runtime::AuthorityBinding,
    ) -> RosterCompactAdmissionProvenanceV2 {
        let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("test root scalar");
        let leaf_key = SigningKey::from_bytes((&[0x34; 32]).into()).expect("test ingress scalar");
        let root = RosterAttestationTrustRootV1::new(
            [0xa1; 32],
            root_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("compressed root key width"),
        )
        .expect("test root");
        let configuration_identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([0x41; 32]),
            SessionConsensusConfigurationId::from_bytes([0x42; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("nonzero test epoch"),
        );
        let now = Timestamp::now_utc();
        let ingress_input = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment: [0x81; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x82; 16],
            operation_tag: 1,
            canonical_capsule_digest: [0x83; 32],
            authenticated_at: now,
            peer_certificate_expires_at: now.add_seconds(60).expect("ingress expiry"),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::TransportIngress,
            configuration_identity,
            scope: admission.scope().digest(),
            subject_identity_commitment: [0x84; 32],
            leaf_epoch: 1,
            key_id: [0x85; 32],
            not_before: now.add_seconds(-60).expect("ingress not before"),
            not_after: now.add_seconds(60).expect("ingress not after"),
            public_key: leaf_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .expect("compressed ingress key width"),
            root_signature: [0; 64],
        };
        certificate.root_signature = TestAttestor::sign(
            &root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                .expect("ingress certificate digest"),
        );
        let _ingress = RosterIngressAttestationV1::issue_from_signed_parts(
            &root,
            certificate.clone(),
            &ingress_input,
            TestAttestor::sign(&leaf_key, ingress_input.digest().expect("ingress digest")),
        )
        .expect("ingress attestation");
        let input = RosterCompactAdmissionProvenanceSigningInputV2::from_canonical_admission(
            configuration_identity,
            &admission
                .to_canonical_bytes()
                .expect("canonical admission bytes"),
            authority.scope().digest(),
            authority.key().clone(),
            authority.owner().clone(),
            authority.fence(),
            authority.credential_id(),
            authority.generation(),
            authority.acquired_at(),
            authority.expires_at(),
            &ingress_input,
            certificate.subject_identity_commitment,
        )
        .expect("compact provenance input");
        RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
            &root,
            certificate,
            &input,
            TestAttestor::sign(
                &leaf_key,
                input.digest().expect("compact provenance digest"),
            ),
        )
        .expect("compact provenance")
    }

    #[async_trait]
    impl FencedMutationRosterExecutorAttestor for TestAttestor {
        fn trust_root(&self) -> super::super::FencedMutationRosterAttestationTrustRootV1 {
            super::super::FencedMutationRosterAttestationTrustRootV1::from_store(self.root.clone())
        }

        fn executor_certificate(
            &self,
        ) -> Result<
            super::super::FencedMutationRosterExecutorCertificatePartsV1,
            super::super::runtime::ExecutorError,
        > {
            Ok(
                super::super::FencedMutationRosterExecutorCertificatePartsV1::from_store(
                    self.certificate.clone(),
                ),
            )
        }

        async fn sign_terminal(
            &self,
            input: &super::super::FencedMutationRosterTerminalAttestationSigningInputV1<'_>,
        ) -> Result<[u8; 64], super::super::runtime::ExecutorError> {
            Ok(Self::sign(&self.key, input.signing_digest()?))
        }

        async fn sign_compact_terminal(
            &self,
            input: &super::super::FencedMutationRosterCompactTerminalMemberSigningInputV2<'_>,
        ) -> Result<[u8; 64], super::super::runtime::ExecutorError> {
            Ok(Self::sign(&self.key, input.signing_digest()?))
        }
    }

    struct Fixture<P> {
        adapter: PublicationAdapter<P, CountingBackend>,
        client: FencedMutationRosterClient,
        publication: EstablishedPublication,
        terminal: super::super::client::PreparedRosterTerminal,
        backend: Arc<CountingBackend>,
        clock: Arc<TestClock>,
        lease_backend: SqliteSessionBackend,
        scope: Scope,
        key: SessionKey,
        roster_id: RosterId,
        original_owner: OwnerId,
        original_admission_fence: FenceToken,
    }

    /// The durable parts of a first-process fixture that a successor may
    /// retain after the affine Established capsule is moved into an
    /// in-flight provider call.
    struct RecoveryFixture {
        backend: Arc<CountingBackend>,
        lease_backend: SqliteSessionBackend,
        scope: Scope,
        key: SessionKey,
        roster_id: RosterId,
        original_owner: OwnerId,
        original_admission_fence: FenceToken,
    }

    impl<P> Fixture<P> {
        fn recovery_fixture(&self) -> RecoveryFixture {
            RecoveryFixture {
                backend: Arc::clone(&self.backend),
                lease_backend: self.lease_backend.clone(),
                scope: self.scope,
                key: self.key.clone(),
                roster_id: self.roster_id,
                original_owner: self.original_owner.clone(),
                original_admission_fence: self.original_admission_fence,
            }
        }
    }

    async fn fixture<P>(provider: Arc<P>) -> Fixture<P>
    where
        P: EstablishedPublicationProvider,
    {
        fixture_with_roster(provider, [0x61; 16]).await
    }

    async fn fixture_with_roster<P>(provider: Arc<P>, roster_bytes: [u8; 16]) -> Fixture<P>
    where
        P: EstablishedPublicationProvider,
    {
        let scope = Scope::from_digest([0x71; 32]);
        let clock = Arc::new(TestClock {
            expired: AtomicBool::new(false),
        });
        let backend = Arc::new(CountingBackend::default());
        let executor_clock: Arc<dyn Clock> = clock.clone();
        let executor = RosterExecutor::new_with_clock(
            Arc::new(ConclusiveMemberProvider::new(scope)),
            Arc::clone(&backend),
            Arc::new(TestAttestor::new(scope)),
            NonZeroUsize::new(1).expect("one provider lane"),
            executor_clock,
        );
        let adapter = executor.publication_adapter(Arc::clone(&provider));
        let client = FencedMutationRosterClient::new(executor, scope);
        let lease_backend = SqliteSessionBackend::in_memory().expect("test lease backend");
        let key = SessionKey {
            tenant: TenantId::from_static("publication-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(bytes::Bytes::from_static(b"publication-key"))
                .expect("bounded test key"),
        };
        let lease = lease_backend
            .acquire(
                &key,
                OwnerId::new("publication-test-owner").expect("bounded test owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("test lease");
        let original_owner = lease.owner().clone();
        let original_admission_fence = lease.fence();
        let members = (0..6)
            .map(|ordinal| {
                Member::new(
                    ordinal,
                    MemberOperationId::from_bytes([ordinal + 1; 16])
                        .expect("nonzero test operation ID"),
                    vec![ordinal],
                    1,
                )
                .expect("bounded test member")
            })
            .collect();
        let roster_id = RosterId::from_bytes(roster_bytes).expect("nonzero test roster ID");
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            roster_id,
            members,
            EstablishedMutation::no_op(),
            b"retained admission plan".to_vec(),
            b"retained terminal checkpoint".to_vec(),
            b"retained terminal result".to_vec(),
        )
        .expect("frozen six-member proposal");
        let mut admission = AdmissionInput::new(lease, Generation::new(1), proposal)
            .expect("authenticated test admission");
        let mut active = match client.admit(&mut admission).await.expect("admit roster") {
            AdmissionOutcome::Admitted(active) => active,
            AdmissionOutcome::NotTransmitted | AdmissionOutcome::OutcomeUnknown(_) => {
                panic!("fixture admission must be conclusive")
            }
        };
        let mut proofs = Vec::new();
        for ordinal in 0..6 {
            let mut member = active
                .member(MemberOrdinal::new(ordinal).expect("bounded ordinal"))
                .expect("issue member once");
            assert!(matches!(
                client
                    .prepare_member(&mut member)
                    .await
                    .expect("prepare member"),
                MemberPrepareOutcome::Prepared
            ));
            match client.execute(&mut member).await.expect("execute member") {
                ExecuteOutcome::Conclusive(proof) => proofs.push(*proof),
                ExecuteOutcome::NotTransmitted | ExecuteOutcome::Ambiguous(_) => {
                    panic!("fixture member effect must be conclusive")
                }
            }
        }
        let proofs = CompleteProofSet::new(proofs).expect("complete proof set");
        let mut terminal = client
            .prepare_terminal(active.for_terminal(), &proofs)
            .await
            .expect("prepare exact terminal");
        let publication = match client
            .terminalize(&mut terminal)
            .await
            .expect("terminalize")
        {
            TerminalizationOutcome::Committed(TerminalReceipt::Established(established)) => {
                established.into_publication()
            }
            TerminalizationOutcome::Committed(TerminalReceipt::Aborted(_))
            | TerminalizationOutcome::NotTransmitted
            | TerminalizationOutcome::OutcomeUnknown => {
                panic!("fixture terminal must be established")
            }
        };
        Fixture {
            adapter,
            client,
            publication,
            terminal,
            backend,
            clock,
            lease_backend,
            scope,
            key,
            roster_id,
            original_owner,
            original_admission_fence,
        }
    }

    /// Model a second process: a distinct executor and local authority
    /// registry, sharing only the durable roster backend, lease source, and
    /// provider journal supplied by the test.
    async fn recover_successor<Q>(
        first: &RecoveryFixture,
        provider: Arc<Q>,
    ) -> (
        PublicationAdapter<Q, CountingBackend>,
        FencedMutationRosterClient,
        EstablishedPublication,
        FenceToken,
    )
    where
        Q: EstablishedPublicationProvider,
    {
        let successor_scope = Scope::from_digest([0xB7; 32]);
        assert_ne!(
            successor_scope, first.scope,
            "the successor publication fixture must exercise a new ingress scope"
        );
        let successor_executor = RosterExecutor::new_with_clock(
            Arc::new(ConclusiveMemberProvider::new(successor_scope)),
            Arc::clone(&first.backend),
            Arc::new(TestAttestor::new(successor_scope)),
            NonZeroUsize::new(1).expect("one provider lane"),
            Arc::new(TestClock {
                expired: AtomicBool::new(false),
            }),
        );
        let successor_adapter = successor_executor.publication_adapter(provider);
        let successor_client = FencedMutationRosterClient::new(successor_executor, successor_scope);
        let successor_lease = first
            .lease_backend
            .acquire(
                &first.key,
                OwnerId::new("publication-test-owner").expect("bounded test owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("same owner can acquire a strictly newer durable fence");
        let successor_fence = successor_lease.fence();
        let recovery = RecoveryInput::new(
            first.roster_id,
            first.original_owner.clone(),
            first.original_admission_fence,
            successor_lease,
            Generation::new(1),
        )
        .expect("valid successor recovery input");
        let successor_publication = match successor_client
            .recover(&recovery)
            .await
            .expect("read exact committed terminal under the successor fence")
        {
            RecoveryOutcome::Terminal(TerminalReceipt::Established(established)) => {
                established.into_publication()
            }
            _ => panic!("recovery must return the exact established terminal"),
        };
        (
            successor_adapter,
            successor_client,
            successor_publication,
            successor_fence,
        )
    }

    fn assert_one_exact_capsule(provider: &DurablePublicationProvider) {
        let snapshots = provider.snapshots();
        assert!(
            !snapshots.is_empty(),
            "provider must observe the retained capsule"
        );
        assert!(
            snapshots.windows(2).all(|pair| pair[0] == pair[1]),
            "status, intent admission, adoption, and recovery must reuse the exact roster/admission/terminal/publication body and current authority"
        );
    }

    #[tokio::test]
    async fn outcome_unknown_is_unacknowledged_until_status_proves_the_exact_publication() {
        let provider = Arc::new(DurablePublicationProvider::ambiguous_then(
            StatusAfterAdopt::Published,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired),
            "a lost adoption outcome cannot acknowledge publication"
        );
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 1);

        let evidence = fixture
            .adapter
            .publish(&mut fixture.publication)
            .await
            .expect("exact provider status proves publication");
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 2);
        let diagnostics = fixture.client.diagnostics();
        assert_eq!(diagnostics.publication_status_calls, 2);
        assert_eq!(diagnostics.publication_begin_calls, 1);
        assert_eq!(diagnostics.publication_adopt_calls, 1);
        assert_eq!(diagnostics.publication_acknowledged, 1);
        assert_eq!(diagnostics.publication_recovery_required, 1);
        assert_eq!(diagnostics.provider_in_flight, 0);
        assert_one_exact_capsule(&provider);
        assert_eq!(
            fixture.backend.terminalizations.load(Ordering::SeqCst),
            1,
            "publication recovery is provider-local and adds no consensus mutation"
        );
        assert_eq!(
            evidence.publication_id().as_bytes(),
            &provider.snapshots()[0].publication_id,
            "the acknowledgement is bound to the durable publication identity"
        );
    }

    #[tokio::test]
    async fn absent_after_ambiguous_adoption_cannot_acknowledge_or_authorize_an_alternate_effect() {
        let provider = Arc::new(DurablePublicationProvider::ambiguous_then(
            StatusAfterAdopt::Absent,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired)
        );
        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired),
            "NotFound is non-exclusionary after an ambiguous adoption"
        );
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 2);
        assert_one_exact_capsule(&provider);
    }

    #[tokio::test]
    async fn recovered_receipt_after_ambiguous_adoption_never_replays_the_external_effect() {
        let provider = Arc::new(DurablePublicationProvider::ambiguous_then(
            StatusAfterAdopt::Absent,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired)
        );
        let mut recovered_publication = match fixture
            .client
            .terminal_status(&mut fixture.terminal)
            .await
            .expect("read exact retained terminal")
        {
            super::super::client::TerminalStatus::Committed(TerminalReceipt::Established(
                established,
            )) => established.into_publication(),
            _ => panic!("fixture status must recover the exact Established terminal"),
        };
        assert_eq!(
            fixture.adapter.publish(&mut recovered_publication).await,
            Err(PublicationAdapterError::RecoveryRequired)
        );
        assert_eq!(
            provider.external_effects.load(Ordering::SeqCst),
            1,
            "a reconstructed receipt can only re-enter provider adoption, never blind-run the effect"
        );
        assert_eq!(fixture.backend.terminalizations.load(Ordering::SeqCst), 1);
        assert_one_exact_capsule(&provider);
    }

    #[tokio::test]
    async fn restarted_provider_and_executor_recover_one_durable_intent_without_a_third_consensus_mutation(
    ) {
        let journal = Arc::new(RestartPublicationJournal::default());
        let (
            backend,
            lease_backend,
            scope,
            key,
            roster_id,
            original_owner,
            original_admission_fence,
        ) = {
            let first_provider = Arc::new(RestartJournalProvider::initial(Arc::clone(&journal)));
            let mut fixture = fixture(Arc::clone(&first_provider)).await;

            assert_eq!(
                fixture.adapter.publish(&mut fixture.publication).await,
                Err(PublicationAdapterError::RecoveryRequired),
                "the first provider completes its sole external effect but loses that reply"
            );
            assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
            assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 1);
            assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
            assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
            assert!(journal.effect_crossed());
            assert!(journal.completion_evidence_durable());
            assert!(matches!(
                journal.state(),
                RestartPublicationState::Attempted
            ));

            // Leaving this block destroys the first provider object, its
            // adapter, client, executor, scheduler, and local authority
            // registry. Only the durable provider journal, committed backend
            // record, and independently durable lease source survive.
            (
                Arc::clone(&fixture.backend),
                fixture.lease_backend.clone(),
                fixture.scope,
                fixture.key.clone(),
                fixture.roster_id,
                fixture.original_owner.clone(),
                fixture.original_admission_fence,
            )
        };

        let restarted_provider = Arc::new(RestartJournalProvider::recover(Arc::clone(&journal)));
        let restarted_clock = Arc::new(TestClock {
            expired: AtomicBool::new(false),
        });
        let restarted_executor_clock: Arc<dyn Clock> = restarted_clock;
        let restarted_executor = RosterExecutor::new_with_clock(
            Arc::new(ConclusiveMemberProvider::new(scope)),
            Arc::clone(&backend),
            Arc::new(TestAttestor::new(scope)),
            NonZeroUsize::new(1).expect("one provider lane"),
            restarted_executor_clock,
        );
        let restarted_adapter =
            restarted_executor.publication_adapter(Arc::clone(&restarted_provider));
        let restarted_client = FencedMutationRosterClient::new(restarted_executor, scope);
        let successor_lease = lease_backend
            .acquire(
                &key,
                OwnerId::new("publication-test-owner").expect("bounded test owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("same owner can acquire a strictly newer durable fence");
        assert!(
            successor_lease.fence().get() > journal.intent().fence.get(),
            "restart recovery must use a fence strictly higher than the original effect"
        );
        let recovery = RecoveryInput::new(
            roster_id,
            original_owner,
            original_admission_fence,
            successor_lease,
            Generation::new(1),
        )
        .expect("valid successor recovery input");
        let mut recovered_publication = match restarted_client
            .recover(&recovery)
            .await
            .expect("read exact committed terminal under the successor fence")
        {
            RecoveryOutcome::Terminal(TerminalReceipt::Established(established)) => {
                established.into_publication()
            }
            _ => panic!("recovery must return the exact established terminal"),
        };

        let evidence = restarted_adapter
            .publish(&mut recovered_publication)
            .await
            .expect("the recreated provider must status the durable effect into one exact ACK");
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 2);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
        assert_eq!(backend.registrations.load(Ordering::SeqCst), 1);
        assert_eq!(backend.terminalizations.load(Ordering::SeqCst), 1);

        let intent = journal.intent();
        let snapshots = journal.snapshots();
        let recovered_status = snapshots
            .last()
            .expect("restarted provider must observe the recovered publication");
        assert_same_durable_publication_body(&intent, recovered_status);
        assert!(
            recovered_status.fence.get() > intent.fence.get(),
            "the exact checkpoint/result and publication identity survive while authority advances"
        );
        assert_eq!(
            evidence.publication_id().as_bytes(),
            &intent.publication_id,
            "the acknowledgement remains bound to the one durable intent identity"
        );
    }

    #[tokio::test]
    async fn durable_publication_provider_rejects_expired_authority_before_any_io() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::initial(Arc::clone(&journal)));
        let mut fixture = fixture(provider).await;
        journal.expire_provider_authority();
        let diagnostics_before = fixture.client.diagnostics();

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired)
        );
        let diagnostics_after = fixture.client.diagnostics();
        assert_eq!(
            diagnostics_after.publication_status_calls,
            diagnostics_before.publication_status_calls + 1,
            "the SDK must enter provider status before provider-clock rejection"
        );
        assert_eq!(
            diagnostics_after.publication_begin_calls,
            diagnostics_before.publication_begin_calls
        );
        assert_eq!(
            diagnostics_after.publication_adopt_calls,
            diagnostics_before.publication_adopt_calls
        );
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert!(journal.snapshots().is_empty());
        assert_eq!(fixture.backend.registrations.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.backend.terminalizations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn backend_current_expiry_rejects_locally_unexpired_authority_before_provider_io() {
        let provider = Arc::new(DurablePublicationProvider::begin_published());
        let mut fixture = fixture(Arc::clone(&provider)).await;
        let diagnostics_before = fixture.client.diagnostics();
        let provider_calls_before = (
            provider.status_calls.load(Ordering::SeqCst),
            provider.begin_calls.load(Ordering::SeqCst),
            provider.adopt_calls.load(Ordering::SeqCst),
            provider.external_effects.load(Ordering::SeqCst),
            provider.snapshots().len(),
        );
        let reads_before = fixture.backend.authority_reads();
        let mutations_before = (
            fixture.backend.registrations.load(Ordering::SeqCst),
            fixture.backend.terminalizations.load(Ordering::SeqCst),
        );

        // The first executor's local test clock remains valid. Only the
        // shared backend's half-open lease read is at expiry, so the adapter
        // must fail before it enters provider status.
        fixture.backend.expire_current_authority_for_read();
        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::AuthorityRejected)
        );

        let diagnostics_after = fixture.client.diagnostics();
        assert_eq!(
            diagnostics_after.publication_status_calls,
            diagnostics_before.publication_status_calls
        );
        assert_eq!(
            diagnostics_after.publication_begin_calls,
            diagnostics_before.publication_begin_calls
        );
        assert_eq!(
            diagnostics_after.publication_adopt_calls,
            diagnostics_before.publication_adopt_calls
        );
        assert_eq!(
            diagnostics_after.publication_acknowledged,
            diagnostics_before.publication_acknowledged
        );
        assert_eq!(
            (
                provider.status_calls.load(Ordering::SeqCst),
                provider.begin_calls.load(Ordering::SeqCst),
                provider.adopt_calls.load(Ordering::SeqCst),
                provider.external_effects.load(Ordering::SeqCst),
                provider.snapshots().len(),
            ),
            provider_calls_before,
            "backend expiry must prevent every publication-provider call and effect"
        );
        assert_eq!(fixture.backend.authority_reads(), reads_before + 1);
        assert_eq!(
            (
                fixture.backend.registrations.load(Ordering::SeqCst),
                fixture.backend.terminalizations.load(Ordering::SeqCst),
            ),
            mutations_before,
            "the current-authority read is not a roster mutation"
        );
    }

    #[tokio::test]
    async fn backend_current_successor_rejects_old_process_before_provider_io_then_successor_publishes(
    ) {
        let journal = Arc::new(RestartPublicationJournal::default());
        let first_provider = Arc::new(RestartJournalProvider::initial(Arc::clone(&journal)));
        let mut fixture = fixture(first_provider).await;
        let stale_fence = EstablishedPublicationCall::from_established(&fixture.publication)
            .expect("SDK-issued stale publication")
            .current_fence();

        let successor_provider = Arc::new(RestartJournalProvider::recover(Arc::clone(&journal)));
        let (successor_adapter, successor_client, mut successor_publication, successor_fence) =
            recover_successor(&fixture.recovery_fixture(), successor_provider).await;
        assert!(successor_fence > stale_fence);
        let calls_before_stale = (
            journal.status_calls.load(Ordering::SeqCst),
            journal.begin_calls.load(Ordering::SeqCst),
            journal.adopt_calls.load(Ordering::SeqCst),
            journal.external_effects.load(Ordering::SeqCst),
            journal.snapshots().len(),
        );
        let stale_diagnostics_before = fixture.client.diagnostics();
        let reads_before_stale = fixture.backend.authority_reads();
        let mutations_before_stale = (
            fixture.backend.registrations.load(Ordering::SeqCst),
            fixture.backend.terminalizations.load(Ordering::SeqCst),
        );

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::AuthorityRejected),
            "the first process's still-locally-current permit must fail at the backend-current read before provider I/O"
        );
        let stale_diagnostics_after = fixture.client.diagnostics();
        assert_eq!(
            stale_diagnostics_after.publication_status_calls,
            stale_diagnostics_before.publication_status_calls,
            "the old SDK process must not enter provider status after the backend-current read rejects it"
        );
        assert_eq!(
            stale_diagnostics_after.publication_begin_calls,
            stale_diagnostics_before.publication_begin_calls
        );
        assert_eq!(
            stale_diagnostics_after.publication_adopt_calls,
            stale_diagnostics_before.publication_adopt_calls
        );
        assert_eq!(
            stale_diagnostics_after.publication_acknowledged,
            stale_diagnostics_before.publication_acknowledged,
            "rejected old authority cannot ACK the established receipt"
        );
        assert_eq!(
            (
                journal.status_calls.load(Ordering::SeqCst),
                journal.begin_calls.load(Ordering::SeqCst),
                journal.adopt_calls.load(Ordering::SeqCst),
                journal.external_effects.load(Ordering::SeqCst),
                journal.snapshots().len(),
            ),
            calls_before_stale,
            "the delayed old fence is rejected before provider I/O"
        );
        assert_eq!(
            fixture.backend.authority_reads(),
            reads_before_stale + 1,
            "the rejected attempt performs only its one read-only preflight"
        );
        assert_eq!(
            (
                fixture.backend.registrations.load(Ordering::SeqCst),
                fixture.backend.terminalizations.load(Ordering::SeqCst),
            ),
            mutations_before_stale,
            "current-authority reads must not add roster mutations"
        );

        successor_adapter
            .publish(&mut successor_publication)
            .await
            .expect("successor publishes only after the old authority was rejected");
        assert_eq!(journal.fence_floor(), successor_fence);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(successor_client.diagnostics().publication_acknowledged, 1);
        assert_eq!(
            (
                fixture.backend.registrations.load(Ordering::SeqCst),
                fixture.backend.terminalizations.load(Ordering::SeqCst),
            ),
            mutations_before_stale,
            "the successor publication remains provider-local"
        );
    }

    #[tokio::test]
    async fn takeover_racing_provider_io_is_fenced_and_post_read_prevents_old_ack() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(GatedRestartJournalProvider::new(Arc::clone(&journal)));
        let fixture = fixture(Arc::clone(&provider)).await;
        let stale_fence = EstablishedPublicationCall::from_established(&fixture.publication)
            .expect("SDK-issued stale publication")
            .current_fence();
        let mutations_before = (
            fixture.backend.registrations.load(Ordering::SeqCst),
            fixture.backend.terminalizations.load(Ordering::SeqCst),
        );

        // Construct the second process and its distinct local registry before
        // advancing the shared durable authority. It cannot touch the
        // provider until recovery below.
        let successor_executor = RosterExecutor::new_with_clock(
            Arc::new(ConclusiveMemberProvider::new(fixture.scope)),
            Arc::clone(&fixture.backend),
            Arc::new(TestAttestor::new(fixture.scope)),
            NonZeroUsize::new(1).expect("one provider lane"),
            Arc::new(TestClock {
                expired: AtomicBool::new(false),
            }),
        );
        let successor_adapter = successor_executor.publication_adapter(Arc::clone(&provider));
        let successor_client = FencedMutationRosterClient::new(successor_executor, fixture.scope);

        let first_begin = provider.wait_for_first_begin();
        let first_adapter = fixture.adapter.clone();
        let first_publication = fixture.publication;
        let first_publish = tokio::spawn(async move {
            let mut publication = first_publication;
            first_adapter.publish(&mut publication).await
        });
        first_begin.await;
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);

        let successor_lease = fixture
            .lease_backend
            .acquire(
                &fixture.key,
                OwnerId::new("publication-test-owner").expect("bounded test owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("same owner can acquire a strictly newer durable fence");
        let successor_fence = successor_lease.fence();
        assert!(successor_fence > stale_fence);
        let recovery = RecoveryInput::new(
            fixture.roster_id,
            fixture.original_owner.clone(),
            fixture.original_admission_fence,
            successor_lease,
            Generation::new(1),
        )
        .expect("valid successor recovery input");
        let mut successor_publication = match successor_client
            .recover(&recovery)
            .await
            .expect("read exact committed terminal under successor authority")
        {
            RecoveryOutcome::Terminal(TerminalReceipt::Established(established)) => {
                established.into_publication()
            }
            _ => panic!("recovery must return the exact established terminal"),
        };

        successor_adapter
            .publish(&mut successor_publication)
            .await
            .expect("successor must fence and reconcile the shared provider journal");
        let calls_after_successor = (
            journal.status_calls.load(Ordering::SeqCst),
            journal.begin_calls.load(Ordering::SeqCst),
            journal.adopt_calls.load(Ordering::SeqCst),
            journal.external_effects.load(Ordering::SeqCst),
            journal.snapshots().len(),
        );
        assert_eq!(calls_after_successor, (2, 1, 1, 1, 4));
        assert_eq!(journal.fence_floor(), successor_fence);
        assert_eq!(successor_client.diagnostics().publication_acknowledged, 1);
        let reads_before_old_postcheck = fixture.backend.authority_reads();

        provider.resume_first_begin();
        assert_eq!(
            first_publish.await.expect("old publication task joins"),
            Err(PublicationAdapterError::RecoveryRequired),
            "provider fencing makes the old in-flight begin ambiguous and its post-read must not ACK"
        );
        assert_eq!(
            fixture.backend.authority_reads(),
            reads_before_old_postcheck + 1,
            "the old provider error is still followed by one backend-current post-read"
        );
        assert_eq!(
            (
                journal.status_calls.load(Ordering::SeqCst),
                journal.begin_calls.load(Ordering::SeqCst),
                journal.adopt_calls.load(Ordering::SeqCst),
                journal.external_effects.load(Ordering::SeqCst),
                journal.snapshots().len(),
            ),
            calls_after_successor,
            "the delayed old provider operation cannot write an intent or effect after the successor floor"
        );
        assert_eq!(fixture.client.diagnostics().publication_acknowledged, 0);
        assert_eq!(
            (
                fixture.backend.registrations.load(Ordering::SeqCst),
                fixture.backend.terminalizations.load(Ordering::SeqCst),
            ),
            mutations_before,
            "neither authority read nor provider takeover adds a roster mutation"
        );
    }

    #[tokio::test]
    async fn only_direct_not_transmitted_restores_the_identical_effect_free_begin_call() {
        let provider = Arc::new(DurablePublicationProvider::not_transmitted_then_published());
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::BeginNotTransmitted)
        );
        fixture
            .adapter
            .publish(&mut fixture.publication)
            .await
            .expect("only the direct non-transmission proof permits this retry");
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 2);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.status_calls.load(Ordering::SeqCst),
            1,
            "the retained direct retry must not replace the call with another status read"
        );
        let diagnostics = fixture.client.diagnostics();
        assert_eq!(diagnostics.publication_begin_not_transmitted, 1);
        assert_eq!(diagnostics.publication_recovery_required, 0);
        assert_one_exact_capsule(&provider);
    }

    #[tokio::test]
    async fn healthy_absent_then_begin_published_is_not_counted_as_recovery() {
        let provider = Arc::new(DurablePublicationProvider::begin_published());
        let mut fixture = fixture(provider).await;

        fixture
            .adapter
            .publish(&mut fixture.publication)
            .await
            .expect("absent status can begin the exact publication intent");

        let diagnostics = fixture.client.diagnostics();
        assert_eq!(diagnostics.publication_status_calls, 1);
        assert_eq!(diagnostics.publication_begin_calls, 1);
        assert_eq!(diagnostics.publication_adopt_calls, 0);
        assert_eq!(diagnostics.publication_acknowledged, 1);
        assert_eq!(diagnostics.publication_recovery_required, 0);
    }

    #[tokio::test]
    async fn healthy_pending_then_adopt_published_is_not_counted_as_recovery() {
        let provider = Arc::new(DurablePublicationProvider::pending_then_published());
        let mut fixture = fixture(provider).await;

        fixture
            .adapter
            .publish(&mut fixture.publication)
            .await
            .expect("pending intent can be adopted into one acknowledgement");

        let diagnostics = fixture.client.diagnostics();
        assert_eq!(diagnostics.publication_status_calls, 1);
        assert_eq!(diagnostics.publication_begin_calls, 1);
        assert_eq!(diagnostics.publication_adopt_calls, 1);
        assert_eq!(diagnostics.publication_acknowledged, 1);
        assert_eq!(diagnostics.publication_recovery_required, 0);
    }

    #[tokio::test]
    async fn expired_authority_rejects_before_any_provider_io() {
        let provider = Arc::new(DurablePublicationProvider::ambiguous_then(
            StatusAfterAdopt::Published,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;
        fixture.clock.expire();

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::AuthorityRejected)
        );
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 0);
        assert!(provider.snapshots().is_empty());
    }

    #[tokio::test]
    async fn legacy_publication_retains_three_operations_and_six_authority_reads() {
        let provider = Arc::new(DurablePublicationProvider::ambiguous_then(
            StatusAfterAdopt::Absent,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;
        let authority_reads_before = fixture.backend.authority_reads();

        assert_eq!(
            fixture.adapter.publish(&mut fixture.publication).await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the unchanged status/begin/adopt path remains ambiguous after its sole effect"
        );
        assert_eq!(
            fixture.backend.authority_reads(),
            authority_reads_before + 6,
            "legacy publication must retain one pre/post authority read around each of status, begin, and adopt"
        );
        assert_eq!(provider.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.begin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.external_effects.load(Ordering::SeqCst), 1);
        assert_one_exact_capsule(&provider);
    }

    #[tokio::test]
    async fn fresh_compound_publication_uses_exactly_one_pre_and_post_authority_read() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::Published,
        ));
        let mut fixture = fixture(provider).await;
        let authority_reads_before = fixture.backend.authority_reads();
        let mutations_before = (
            fixture.backend.registrations.load(Ordering::SeqCst),
            fixture.backend.terminalizations.load(Ordering::SeqCst),
        );

        let evidence = fixture
            .adapter
            .publish_fresh_established(&mut fixture.publication)
            .await
            .expect("the fresh compound provider publishes one exact identity");

        assert_eq!(
            fixture.backend.authority_reads(),
            authority_reads_before + 2
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
        assert_eq!(
            (
                fixture.backend.registrations.load(Ordering::SeqCst),
                fixture.backend.terminalizations.load(Ordering::SeqCst),
            ),
            mutations_before,
            "the compound publication remains provider-local and cannot add a third roster mutation"
        );
        assert_eq!(
            evidence.publication_id().as_bytes(),
            &journal.intent().publication_id,
            "the acknowledgement remains bound to the durable journal identity"
        );
    }

    #[tokio::test]
    async fn fresh_crash_before_attempt_recovers_by_status_adopt_after_lease_reacquisition() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let first_provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::ReservedThenUnknown,
        ));
        let mut fixture = fixture(Arc::clone(&first_provider)).await;

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "a crash after Reserved cannot acknowledge or retain fresh effect authority"
        );
        assert!(matches!(journal.state(), RestartPublicationState::Reserved));
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        let intent = journal.intent();

        let successor_provider = Arc::new(RestartJournalProvider::recover(Arc::clone(&journal)));
        let (successor_adapter, _, mut recovered, successor_fence) =
            recover_successor(&fixture.recovery_fixture(), successor_provider).await;
        successor_adapter
            .publish_fresh_established(&mut recovered)
            .await
            .expect("a recovered capsule may only status/adopt the same Reserved identity");

        assert!(successor_fence > intent.fence);
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
        for snapshot in journal.snapshots() {
            assert_same_durable_publication_body(&intent, &snapshot);
        }
    }

    #[tokio::test]
    async fn fresh_attempted_unknown_receipt_recovery_never_replays_the_effect() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::EffectThenUnknown,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the lost post-attempt reply must remain unacknowledged"
        );
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);

        let mut recovered = match fixture
            .client
            .terminal_status(&mut fixture.terminal)
            .await
            .expect("read exact retained terminal")
        {
            super::super::client::TerminalStatus::Committed(TerminalReceipt::Established(
                established,
            )) => established.into_publication(),
            _ => panic!("terminal status must return the exact Established receipt"),
        };
        fixture
            .adapter
            .publish_fresh_established(&mut recovered)
            .await
            .expect("a status-derived handle adopts the completed attempted identity");

        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
    }

    #[tokio::test]
    async fn fresh_effect_before_durable_completion_evidence_recovers_without_replay() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::EffectBeforeCompletionUnknown,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "a crash or cancellation after the effect but before completion evidence cannot ACK"
        );
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
        assert!(journal.effect_crossed());
        assert!(
            !journal.completion_evidence_durable(),
            "the test cut is specifically after the external effect and before durable completion"
        );

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the same capsule is status/adopt-only once the effect may have crossed"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
    }

    #[tokio::test]
    async fn cancellation_after_attempt_demotes_the_same_capsule_to_status_adopt_only() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(GatedFreshJournalProvider::new(Arc::clone(&journal)));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        let exact_capsule_before = CallSnapshot::capture(
            &EstablishedPublicationCall::from_established(&fixture.publication)
                .expect("the original affine capsule is SDK-issued"),
        );
        let mut attempted = Box::pin(provider.wait_for_attempt());
        let mut in_flight = Box::pin(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication),
        );
        tokio::select! {
            result = &mut in_flight => {
                panic!("fresh request must still be paused at Attempted, got {result:?}")
            }
            _ = &mut attempted => {}
        }
        drop(in_flight);

        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        let exact_capsule_after = CallSnapshot::capture(
            &EstablishedPublicationCall::from_established(&fixture.publication)
                .expect("cancellation must retain the same affine capsule"),
        );
        assert_eq!(exact_capsule_after, exact_capsule_before);
        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the same cancelled capsule may only status/adopt the retained Attempted identity"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fresh_pre_effect_takeover_reacquisition_fences_the_old_call_before_effect() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(GatedFreshJournalProvider::new(Arc::clone(&journal)));
        let fixture = fixture(Arc::clone(&provider)).await;
        let stale_fence = EstablishedPublicationCall::from_established(&fixture.publication)
            .expect("SDK-issued fresh publication")
            .current_fence();
        let recovery_fixture = fixture.recovery_fixture();

        let reached_attempt = provider.wait_for_attempt();
        let first_adapter = fixture.adapter.clone();
        let first_publication = fixture.publication;
        let first_publish = tokio::spawn(async move {
            let mut publication = first_publication;
            first_adapter
                .publish_fresh_established(&mut publication)
                .await
        });
        reached_attempt.await;
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
        assert!(!journal.effect_crossed());
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);

        // A successor reacquires the lease while the old provider future is
        // suspended at the durable Attempted-before-effect boundary. Its
        // recovery-only status/adopt path raises the provider fence, but it
        // cannot infer receipt evidence or replay the pending effect.
        let (successor_adapter, successor_client, mut recovered, successor_fence) =
            recover_successor(&recovery_fixture, Arc::clone(&provider)).await;
        assert!(
            successor_fence > stale_fence,
            "the successor must reacquire a strictly newer durable lease fence"
        );
        assert_eq!(
            successor_adapter
                .publish_fresh_established(&mut recovered)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the successor may fence the Attempted identity but cannot invent completion evidence"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.fence_floor(), successor_fence);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert_eq!(successor_client.diagnostics().publication_acknowledged, 0);

        let reads_before_old_completion = fixture.backend.authority_reads();
        provider.resume();
        assert_eq!(
            first_publish
                .await
                .expect("old fresh publication task joins"),
            Err(PublicationAdapterError::RecoveryRequired),
            "the delayed stale provider call must fail closed after its pre-effect fence recheck"
        );
        assert_eq!(
            fixture.backend.authority_reads(),
            reads_before_old_completion + 1,
            "the completed old invocation still performs its one post-effect authority read"
        );
        assert_eq!(fixture.client.diagnostics().publication_acknowledged, 0);
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert!(!journal.effect_crossed());
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
    }

    #[tokio::test]
    async fn fresh_post_effect_takeover_and_lease_renewal_fence_the_old_ack() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(GatedFreshJournalProvider::after_effect(Arc::clone(
            &journal,
        )));
        let fixture = fixture(Arc::clone(&provider)).await;
        let stale_fence = EstablishedPublicationCall::from_established(&fixture.publication)
            .expect("SDK-issued stale fresh publication")
            .current_fence();
        let recovery_fixture = fixture.recovery_fixture();

        let reached_effect = provider.wait_for_effect();
        let first_adapter = fixture.adapter.clone();
        let first_publication = fixture.publication;
        let first_publish = tokio::spawn(async move {
            let mut publication = first_publication;
            first_adapter
                .publish_fresh_established(&mut publication)
                .await
        });
        reached_effect.await;
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Attempted
        ));
        assert!(journal.effect_crossed());
        assert!(journal.completion_evidence_durable());
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);

        let (successor_adapter, successor_client, mut recovered, successor_fence) =
            recover_successor(&recovery_fixture, Arc::clone(&provider)).await;
        assert!(
            successor_fence > stale_fence,
            "the successor must hold a strictly newer durable lease fence"
        );
        successor_adapter
            .publish_fresh_established(&mut recovered)
            .await
            .expect("a recovered capsule may status/adopt durable completion evidence");
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(journal.fence_floor(), successor_fence);
        assert_eq!(successor_client.diagnostics().publication_acknowledged, 1);

        let reads_before_old_postcheck = fixture.backend.authority_reads();
        provider.resume();
        assert_eq!(
            first_publish
                .await
                .expect("old fresh publication task joins"),
            Err(PublicationAdapterError::RecoveryRequired),
            "a post-effect fresh reply under a superseded lease must never ACK"
        );
        assert_eq!(
            fixture.backend.authority_reads(),
            reads_before_old_postcheck + 1,
            "the completed old fresh invocation performs its one post-effect check"
        );
        assert_eq!(fixture.client.diagnostics().publication_acknowledged, 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
    }

    #[tokio::test]
    async fn fresh_compound_rejects_stale_backend_authority_before_provider_io() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::Published,
        ));
        let mut fixture = fixture(provider).await;
        let reads_before = fixture.backend.authority_reads();
        fixture.backend.expire_current_authority_for_read();

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::AuthorityRejected)
        );
        assert_eq!(fixture.backend.authority_reads(), reads_before + 1);
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert!(journal.snapshots().is_empty());
    }

    #[tokio::test]
    async fn provider_compound_duplicate_is_serialized_to_one_effect() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(ConcurrentFreshJournalProvider::new(Arc::clone(&journal)));
        let fixture = fixture(Arc::clone(&provider)).await;
        let call = EstablishedPublicationCall::from_established(&fixture.publication)
            .expect("fixture has one exact fresh publication");

        let (first, second) = tokio::join!(
            provider.publish_fresh_established(&call),
            provider.publish_fresh_established(&call),
        );
        assert!(matches!(
            first,
            Ok(PublicationProviderOutcome::Published(_))
        ));
        assert!(matches!(
            second,
            Ok(PublicationProviderOutcome::Published(_))
        ));
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 1);
        assert_eq!(journal.intent_count(), 1);
        assert!(journal.effect_crossed());
        assert!(journal.completion_evidence_durable());
        assert!(matches!(
            journal.state(),
            RestartPublicationState::Published
        ));
    }

    #[tokio::test]
    async fn distinct_fresh_publication_identities_do_not_collide() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::Published,
        ));
        let mut first = fixture(Arc::clone(&provider)).await;
        first
            .adapter
            .publish_fresh_established(&mut first.publication)
            .await
            .expect("first journal identity publishes");
        let retained = journal.intent();
        let mut foreign = fixture_with_roster(Arc::clone(&provider), [0x62; 16]).await;
        foreign
            .adapter
            .publish_fresh_established(&mut foreign.publication)
            .await
            .expect("a distinct immutable publication ID owns a distinct journal entry");
        assert_eq!(journal.intent_count(), 2);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 2);
        assert!(
            journal
                .snapshots()
                .iter()
                .any(|snapshot| snapshot.publication_id != retained.publication_id),
            "a distinct roster publication must be retained under its own stable journal key"
        );
    }

    #[tokio::test]
    async fn same_stable_fresh_identity_with_a_different_valid_body_is_sticky_payload_conflict() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::Published,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;
        let exact = CallSnapshot::capture(
            &EstablishedPublicationCall::from_established(&fixture.publication)
                .expect("fixture has one exact fresh publication"),
        );

        // Retain a different, independently SDK-created call body under this
        // identity. Its commitments were computed by `fixture_with_roster`, so
        // this is not a synthetic result-byte mutation that no real call could
        // produce. Overwriting only the stable identity models a pre-existing
        // foreign journal entry that must remain sticky and fail closed.
        let foreign = fixture_with_roster(Arc::clone(&provider), [0x62; 16]).await;
        let mut retained_foreign_body = CallSnapshot::capture(
            &EstablishedPublicationCall::from_established(&foreign.publication)
                .expect("foreign fixture has one independently committed body"),
        );
        assert_ne!(retained_foreign_body.publication_id, exact.publication_id);
        assert_ne!(
            retained_foreign_body.payload_commitment, exact.payload_commitment,
            "the independently computed commitment must bind the changed body"
        );
        retained_foreign_body.publication_id = exact.publication_id;
        journal
            .reserve_for_test(retained_foreign_body.clone())
            .expect("the test may retain one foreign valid body before the real provider call");

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::PayloadConflict),
            "the real compound provider conflict must surface through the adapter"
        );
        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::PayloadConflict),
            "the same conflicted capsule must re-observe the sticky body conflict by status only"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert_eq!(journal.intent_count(), 1);
        assert_eq!(journal.intent(), retained_foreign_body);
        assert_eq!(journal.fence_floor(), exact.fence);
        assert_eq!(journal.snapshots(), vec![exact.clone(), exact]);
    }

    #[tokio::test]
    async fn fresh_direct_nontransmission_retries_only_the_same_compound_request() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::NotTransmitted,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::FreshNotTransmitted)
        );
        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::FreshNotTransmitted),
            "only the exact fresh compound request regains retry authority"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        let snapshots = journal.snapshots();
        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            snapshots[0], snapshots[1],
            "direct non-transmission may retry only the exact same fresh compound call"
        );
    }

    #[tokio::test]
    async fn legacy_nontransmission_from_fresh_compound_is_status_adopt_only() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::LegacyNotTransmitted,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;
        let exact_capsule = CallSnapshot::capture(
            &EstablishedPublicationCall::from_established(&fixture.publication)
                .expect("fixture has one exact fresh capsule"),
        );

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "legacy NotTransmitted never proves fresh compound retry authority"
        );
        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "the same capsule is status/adopt-only after legacy non-transmission"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
        assert_eq!(
            journal.snapshots(),
            vec![exact_capsule.clone(), exact_capsule]
        );
    }

    #[tokio::test]
    async fn fresh_not_found_fails_closed_and_cannot_restore_effect_authority() {
        let journal = Arc::new(RestartPublicationJournal::default());
        let provider = Arc::new(RestartJournalProvider::fresh(
            Arc::clone(&journal),
            FreshPublicationReply::Absent,
        ));
        let mut fixture = fixture(Arc::clone(&provider)).await;

        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired)
        );
        assert_eq!(
            fixture
                .adapter
                .publish_fresh_established(&mut fixture.publication)
                .await,
            Err(PublicationAdapterError::RecoveryRequired),
            "a post-ambiguity NotFound must route only to status/adopt"
        );
        assert_eq!(journal.fresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(journal.begin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.adopt_calls.load(Ordering::SeqCst), 0);
        assert_eq!(journal.external_effects.load(Ordering::SeqCst), 0);
    }
}
