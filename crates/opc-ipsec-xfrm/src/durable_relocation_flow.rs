//! Namespace-serialized durable SA relocation protocol.

use std::fmt;

use crate::durable_relocation::{
    DurableRelocationRecord, XfrmSaRelocationDurableError, XfrmSaRelocationDurablePhase,
    XfrmSaRelocationOperationGeneration, XfrmSaRelocationOperationId,
    XfrmSaRelocationPreEffectProof, XfrmSaRelocationRecoveryHandle, XfrmSaRelocationRecoveryStore,
};
use crate::model::validate_relocate_sa_request;
use crate::{
    QuerySaRequest, RelocateSaRequest, RemoveSaRequest, SaRelocationIdentity, XfrmBackend,
    XfrmError, XfrmId,
};

/// Durable terminal result of one exact SA relocation.
///
/// Every variant carries an authenticated opaque handle. The handle is only
/// correlation data until the same bound store authenticates its current
/// record; its `Debug` and `Display` forms never expose identity material.
#[non_exhaustive]
pub enum XfrmSaRelocationDurableOutcome {
    /// The backend acknowledged the relocation and durable terminal proof was
    /// published before this result became visible.
    Relocated(XfrmSaRelocationRecoveryHandle),
    /// A deterministic non-indeterminate backend rejection proved that the
    /// relocation made no mutation.
    NoMutation(XfrmSaRelocationRecoveryHandle),
    /// Ownership cannot be proved. Recovery must retain state and perform no
    /// deletion. A live call carries its value-free backend failure; a
    /// restored `Issuing` record has no recoverable source value.
    Indeterminate {
        /// Authenticated correlation handle for the fail-closed record.
        handle: XfrmSaRelocationRecoveryHandle,
        /// Observed redaction-safe backend result, when this process saw it.
        source: Option<XfrmError>,
    },
}

impl XfrmSaRelocationDurableOutcome {
    /// Stable, value-free outcome label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Relocated(_) => "relocated",
            Self::NoMutation(_) => "no_mutation",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }

    /// Authenticated opaque correlation handle.
    pub const fn handle(&self) -> &XfrmSaRelocationRecoveryHandle {
        match self {
            Self::Relocated(handle) | Self::NoMutation(handle) => handle,
            Self::Indeterminate { handle, .. } => handle,
        }
    }

    /// Redaction-safe backend failure observed by the current process.
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::Indeterminate { source, .. } => source.as_ref(),
            Self::Relocated(_) | Self::NoMutation(_) => None,
        }
    }
}

impl fmt::Debug for XfrmSaRelocationDurableOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmSaRelocationDurableOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

/// Deterministic disposition of a durable relocation record after process
/// loss.
#[non_exhaustive]
pub enum XfrmSaRelocationRestartOutcome {
    /// A prepared or explicit no-mutation record was retired without a
    /// backend removal.
    NoMutation,
    /// Fresh exact readback proved that the current and target SA identity
    /// are absent, without claiming that the relocation made no mutation.
    StateAbsent,
    /// The relocation was already proven complete; the terminal proof is
    /// returned idempotently and no deletion is ever authorized.
    Relocated,
    /// Exact owned residue was absent or removed and the record was retired.
    OwnedResidueRetired,
    /// A pre-effect proof proved state before the effect was admitted, and
    /// the fresh readback is foreign to this operation. The record was
    /// retired without any deletion; the foreign state was left untouched.
    ForeignUntouched,
    /// The operation may have mutated state, but a classification could not
    /// be completed (for example an unreadable readback). No deletion was
    /// attempted and the record stays unresolved.
    Indeterminate,
    /// The durable record is inconsistent in a way this boundary cannot
    /// safely repair (for example a stale writer epoch or a missing or
    /// inconsistent proof). The record is retained and continues to gate
    /// cooperating writers; product repair is required before any deletion
    /// may be considered.
    RepairRequired,
    /// Exact removal failed after `RemovalAdmitted` was made durable. The
    /// record remains retryable and blocks a cooperating replacement.
    RemovalPending {
        /// Redaction-safe backend failure.
        source: XfrmError,
    },
    /// Cleanup had already completed.
    Retired,
}

impl XfrmSaRelocationRestartOutcome {
    /// Stable, value-free recovery label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoMutation => "no_mutation",
            Self::StateAbsent => "state_absent",
            Self::Relocated => "relocated",
            Self::OwnedResidueRetired => "owned_residue_retired",
            Self::ForeignUntouched => "foreign_untouched",
            Self::Indeterminate => "indeterminate",
            Self::RepairRequired => "repair_required",
            Self::RemovalPending { .. } => "removal_pending",
            Self::Retired => "retired",
        }
    }

    /// Redaction-safe backend removal failure, when retry remains required.
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::RemovalPending { source } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Debug for XfrmSaRelocationRestartOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmSaRelocationRestartOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

/// Deterministic pre-effect rejection while admitting one prepared durable
/// relocation.
///
/// The run handler decides whether the authority is consumed or returned for
/// an exact retry: a mismatching current state consumes it, while a proved
/// target conflict or an untrustworthy readback returns it with no durable
/// change.
#[derive(Debug)]
pub(crate) enum XfrmSaRelocationPreEffectRejection {
    /// The old-identity readback is absent or does not exactly match the
    /// bound current identity; the request is deterministic mismatch and the
    /// authority is consumed.
    CurrentStateMismatch,
    /// The distinct target identity is already present before the effect;
    /// the conflict is deterministic and the authority is returned.
    TargetConflict,
    /// A readback could not be trusted; the authority is returned.
    ReadbackFailed(XfrmError),
}

pub(crate) fn prepare_durable_sa_relocation(
    store: &XfrmSaRelocationRecoveryStore,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
) -> Result<XfrmSaRelocationRecoveryHandle, XfrmSaRelocationDurableError> {
    // A narrow lookup mark can never produce the exact unconditional removal
    // identity; report it distinctly before the general request validation.
    crate::model::validate_exact_lookup_mark(request.current.mark, "relocation.current.mark")
        .map_err(|_| XfrmSaRelocationDurableError::NonExactRemovalIdentity)?;
    validate_relocate_sa_request(request).map_err(|_| XfrmSaRelocationDurableError::Malformed)?;
    let fingerprints = store.fingerprints_for_request(request)?;
    store.prepare(operation_id, operation_generation, fingerprints)
}

/// Observe the current durable phase for one exact operation.
///
/// This direct read holds the store's process-local try-lock lease, so it
/// contends with an in-flight admitted run on the actor's clone of the same
/// open store exactly like [`XfrmSaRelocationRecoveryStore::inspect`].
pub(crate) fn durable_sa_relocation_phase(
    store: &XfrmSaRelocationRecoveryStore,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
) -> Result<XfrmSaRelocationDurablePhase, XfrmSaRelocationDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    store
        .restore(operation_id, operation_generation, fingerprints)
        .map(|record| record.phase)
}

pub(crate) fn validate_durable_sa_relocation_admission(
    store: &XfrmSaRelocationRecoveryStore,
    prepared: &XfrmSaRelocationRecoveryHandle,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
) -> Result<(), XfrmSaRelocationDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore_handle(prepared, fingerprints)?;
    if record.operation_id != operation_id
        || record.operation_generation != operation_generation
        || record.phase != XfrmSaRelocationDurablePhase::Prepared
    {
        return Err(XfrmSaRelocationDurableError::WrongBinding);
    }
    Ok(())
}

/// The relocated SA identity: the current identity with the new destination.
fn relocated_sa_id(request: &RelocateSaRequest) -> XfrmId {
    XfrmId {
        destination: request.new_destination,
        ..request.current.id
    }
}

fn query_for_identity(id: &XfrmId, request: &RelocateSaRequest) -> QuerySaRequest {
    let mut query = QuerySaRequest::new(id.destination, id.protocol, id.spi);
    if let Some(mark) = request.current.mark {
        query = query.with_mark(mark);
    }
    query
}

/// Exact identity readback classified for recovery.
enum IdentityReadback {
    /// The identity is present.
    Present(SaRelocationIdentity),
    /// The identity is definitively absent.
    Absent,
    /// The readback cannot be trusted.
    Unreadable,
}

async fn readback_identity<B>(
    backend: &B,
    id: &XfrmId,
    request: &RelocateSaRequest,
) -> IdentityReadback
where
    B: XfrmBackend + ?Sized,
{
    match backend
        .query_sa_relocation_identity(query_for_identity(id, request))
        .await
    {
        Ok(identity) => IdentityReadback::Present(identity),
        Err(XfrmError::NotFound) => IdentityReadback::Absent,
        Err(_) => IdentityReadback::Unreadable,
    }
}

/// The identity the relocation effect leaves at the target tuple: the bound
/// current identity with the relocated destination, new source address, and
/// resulting encapsulation (mirrors the backend's relocated-state proof).
fn relocated_identity_matches(
    request: &RelocateSaRequest,
    observed: &SaRelocationIdentity,
) -> bool {
    let mut expected = request.current.clone();
    expected.id = relocated_sa_id(request);
    expected.source_address = request.new_source_address;
    expected.encap = request.encap.resulting(request.current.encap);
    *observed == expected
}

/// Witness the pre-effect proof immediately before `Prepared -> Issuing`.
///
/// The old identity must be read back exactly equal to the bound current
/// identity; an absent or mismatching old identity is a deterministic
/// current-state mismatch. For a distinct target identity, a present target
/// is a deterministic conflict and an absent target is the `TargetAbsent`
/// proof. For a same-identity relocation the exact current readback itself
/// witnesses `SameIdentityWitnessed`. An untrustworthy readback rejects
/// without any durable change.
pub(crate) async fn witness_sa_relocation_pre_effect_proof<B>(
    backend: &B,
    request: &RelocateSaRequest,
) -> Result<XfrmSaRelocationPreEffectProof, XfrmSaRelocationPreEffectRejection>
where
    B: XfrmBackend + ?Sized,
{
    let observed = match backend
        .query_sa_relocation_identity(query_for_identity(&request.current.id, request))
        .await
    {
        Ok(identity) => identity,
        Err(XfrmError::NotFound) => {
            return Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch)
        }
        Err(source) => return Err(XfrmSaRelocationPreEffectRejection::ReadbackFailed(source)),
    };
    if observed != request.current {
        return Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch);
    }
    let target_id = relocated_sa_id(request);
    if target_id == request.current.id {
        // Encapsulation and/or source-only relocation: the exact current
        // identity readback above is the target witness by construction.
        return Ok(XfrmSaRelocationPreEffectProof::SameIdentityWitnessed);
    }
    match backend
        .query_sa_relocation_identity(query_for_identity(&target_id, request))
        .await
    {
        Ok(_) => Err(XfrmSaRelocationPreEffectRejection::TargetConflict),
        Err(XfrmError::NotFound) => Ok(XfrmSaRelocationPreEffectProof::TargetAbsent),
        Err(source) => Err(XfrmSaRelocationPreEffectRejection::ReadbackFailed(source)),
    }
}

pub(crate) async fn issue_durable_sa_relocation<B>(
    store: &XfrmSaRelocationRecoveryStore,
    prepared: &XfrmSaRelocationRecoveryHandle,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
    backend: &B,
    pre_effect_proof: XfrmSaRelocationPreEffectProof,
) -> Result<XfrmSaRelocationDurableOutcome, XfrmSaRelocationDurableError>
where
    B: XfrmBackend + ?Sized,
{
    validate_durable_sa_relocation_admission(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
    )?;

    let issuing = store.transition(
        prepared,
        XfrmSaRelocationDurablePhase::Prepared,
        XfrmSaRelocationDurablePhase::Issuing,
        Some(pre_effect_proof),
    )?;
    let result = backend.relocate_sa(request.clone()).await;
    // Every non-indeterminate `relocate_sa` failure is provably no mutation:
    // pre-effect validation/preflight failures, kernel ack rejections with a
    // verified-intact readback, capability-missing rejections with a
    // verified-intact readback, and DSCP-gate rejections before MIGRATE. The
    // backend maps every post-MIGRATE ambiguity to `StateIndeterminate`.
    let (phase, source) = match result {
        Ok(()) => (XfrmSaRelocationDurablePhase::Relocated, None),
        Err(source @ XfrmError::StateIndeterminate { .. }) => {
            (XfrmSaRelocationDurablePhase::Indeterminate, Some(source))
        }
        Err(_) => (XfrmSaRelocationDurablePhase::NoMutation, None),
    };
    let terminal = store.transition(
        &store.handle_for_record(&issuing)?,
        XfrmSaRelocationDurablePhase::Issuing,
        phase,
        None,
    )?;
    let handle = store.handle_for_record(&terminal)?;
    Ok(match phase {
        XfrmSaRelocationDurablePhase::Relocated => {
            XfrmSaRelocationDurableOutcome::Relocated(handle)
        }
        XfrmSaRelocationDurablePhase::NoMutation => {
            XfrmSaRelocationDurableOutcome::NoMutation(handle)
        }
        XfrmSaRelocationDurablePhase::Indeterminate => {
            XfrmSaRelocationDurableOutcome::Indeterminate { handle, source }
        }
        _ => return Err(XfrmSaRelocationDurableError::InvalidTransition),
    })
}

/// Process-loss detector seam: drive a prepared relocation to a durable
/// `Issuing` record and stop before the terminal publication.
///
/// This reproduces the exact crash window that `issue_durable_sa_relocation`
/// would leave if the process died between the `Issuing` publication and the
/// terminal record. When `admit_backend_effect` is true the relocation is
/// invoked exactly as the real effect admission does (the writer epoch was
/// already burned by the `Issuing` transition), so the kernel state moved
/// while the record remains `Issuing`; when false the backend is never
/// touched. No terminal phase is published, so the record stays unresolved
/// and recoverable. This is only used by privileged crash detectors and
/// never grants deletion authority.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_sa_relocation_at_issuing<B>(
    store: &XfrmSaRelocationRecoveryStore,
    prepared: &XfrmSaRelocationRecoveryHandle,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
    backend: &B,
    pre_effect_proof: XfrmSaRelocationPreEffectProof,
    admit_backend_effect: bool,
) -> Result<(), XfrmSaRelocationDurableError>
where
    B: XfrmBackend + ?Sized,
{
    validate_durable_sa_relocation_admission(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
    )?;
    store.transition(
        prepared,
        XfrmSaRelocationDurablePhase::Prepared,
        XfrmSaRelocationDurablePhase::Issuing,
        Some(pre_effect_proof),
    )?;
    if admit_backend_effect {
        // Simulate the kernel accepting the effect before the terminal record
        // is published. The outcome is intentionally ignored: a crash here
        // leaves no durable terminal result regardless of success.
        let _ = backend.relocate_sa(request.clone()).await;
    }
    Ok(())
}

/// The exact unconditional removal identity of one relocation: the target SA
/// destination with the unchanged SPI, protocol, and lookup mark.
pub(crate) fn exact_removal_request(request: &RelocateSaRequest) -> RemoveSaRequest {
    RemoveSaRequest {
        destination: request.new_destination,
        protocol: request.current.id.protocol,
        spi: request.current.id.spi,
        mark: request.current.mark,
    }
}

pub(crate) async fn recover_durable_sa_relocation<B>(
    store: &XfrmSaRelocationRecoveryStore,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: &RelocateSaRequest,
    backend: &B,
) -> Result<XfrmSaRelocationRestartOutcome, XfrmSaRelocationDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let removal = exact_removal_request(request);
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore(operation_id, operation_generation, fingerprints)?;

    match record.phase {
        XfrmSaRelocationDurablePhase::Prepared => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmSaRelocationRestartOutcome::NoMutation)
        }
        XfrmSaRelocationDurablePhase::NoMutation => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmSaRelocationDurablePhase::NoMutation,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmSaRelocationRestartOutcome::NoMutation)
        }
        XfrmSaRelocationDurablePhase::Relocated => {
            // Terminal proof: recovery returns it idempotently and never
            // deletes after terminal publication.
            Ok(XfrmSaRelocationRestartOutcome::Relocated)
        }
        XfrmSaRelocationDurablePhase::StateAbsent => {
            Ok(XfrmSaRelocationRestartOutcome::StateAbsent)
        }
        XfrmSaRelocationDurablePhase::RemovalAdmitted => {
            retire_admitted(store, record, &removal, backend).await
        }
        XfrmSaRelocationDurablePhase::Issuing | XfrmSaRelocationDurablePhase::Indeterminate => {
            reconcile_unresolved(store, record, request, &removal, backend).await
        }
        XfrmSaRelocationDurablePhase::Retired => Ok(XfrmSaRelocationRestartOutcome::Retired),
    }
}

/// Reconcile an `Issuing` or `Indeterminate` record by combining its durable
/// pre-effect proof with fresh exact readbacks of the old and target
/// identities.
///
/// The proof was witnessed before the backend effect was admitted. Because
/// the writer gate excluded every other cooperating writer for the whole time
/// the record remained unresolved, the proof plus the current readbacks are
/// sufficient to classify both identities:
///
/// Different identities (`TargetAbsent`): an intact old identity proves the
/// atomic move never happened (a present target is foreign, because an atomic
/// move cannot duplicate); an absent old identity with a target matching the
/// relocation expectation is this operation's unpublished residue and is
/// removed exactly; every other combination is foreign or externally removed
/// and authorizes no deletion.
///
/// Same identity (`SameIdentityWitnessed`): the single shared readback either
/// still matches the bound current identity (never happened), matches the
/// relocation expectation (happened; remove exactly), matches neither
/// (foreign), or is absent (externally removed).
///
/// A readback failure leaves the record unresolved and retryable. A durable
/// anomaly (stale epoch, missing proof, or proof inconsistent with the bound
/// request) is classified for repair and the record keeps gating cooperating
/// writers.
async fn reconcile_unresolved<B>(
    store: &XfrmSaRelocationRecoveryStore,
    record: DurableRelocationRecord,
    request: &RelocateSaRequest,
    removal: &RemoveSaRequest,
    backend: &B,
) -> Result<XfrmSaRelocationRestartOutcome, XfrmSaRelocationDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let phase = record.phase;
    let Some(proof) = record.pre_effect_proof else {
        return Ok(XfrmSaRelocationRestartOutcome::RepairRequired);
    };
    if !store.record_writer_epoch_is_current(&record)? {
        return Ok(XfrmSaRelocationRestartOutcome::RepairRequired);
    }
    let same_identity = relocated_sa_id(request) == request.current.id;
    // Proof/request consistency is validated fail-closed: `TargetAbsent`
    // requires a changed XfrmId and `SameIdentityWitnessed` requires an
    // unchanged one, exactly as derived from the bound request.
    let consistent = match proof {
        XfrmSaRelocationPreEffectProof::TargetAbsent => !same_identity,
        XfrmSaRelocationPreEffectProof::SameIdentityWitnessed => same_identity,
    };
    if !consistent {
        return Ok(XfrmSaRelocationRestartOutcome::RepairRequired);
    }

    let old = readback_identity(backend, &request.current.id, request).await;
    if same_identity {
        let handle = store.handle_for_record(&record)?;
        return match old {
            IdentityReadback::Present(identity) if identity == request.current => {
                retire_through_no_mutation(store, &handle, phase)?;
                Ok(XfrmSaRelocationRestartOutcome::NoMutation)
            }
            IdentityReadback::Present(identity)
                if relocated_identity_matches(request, &identity) =>
            {
                let admitted = store.transition(
                    &handle,
                    phase,
                    XfrmSaRelocationDurablePhase::RemovalAdmitted,
                    None,
                )?;
                retire_admitted(store, admitted, removal, backend).await
            }
            IdentityReadback::Present(_) => {
                retire_through_no_mutation(store, &handle, phase)?;
                Ok(XfrmSaRelocationRestartOutcome::ForeignUntouched)
            }
            IdentityReadback::Absent => {
                publish_state_absent(store, &handle, phase)?;
                Ok(XfrmSaRelocationRestartOutcome::StateAbsent)
            }
            IdentityReadback::Unreadable => Ok(XfrmSaRelocationRestartOutcome::Indeterminate),
        };
    }

    let target = readback_identity(backend, &relocated_sa_id(request), request).await;
    if matches!(old, IdentityReadback::Unreadable) || matches!(target, IdentityReadback::Unreadable)
    {
        return Ok(XfrmSaRelocationRestartOutcome::Indeterminate);
    }
    let old_intact =
        matches!(&old, IdentityReadback::Present(identity) if *identity == request.current);
    let old_absent = matches!(old, IdentityReadback::Absent);
    let target_relocated = matches!(&target, IdentityReadback::Present(identity) if relocated_identity_matches(request, identity));
    let target_absent = matches!(target, IdentityReadback::Absent);

    let handle = store.handle_for_record(&record)?;
    if old_intact {
        // The atomic move cannot duplicate: with the old identity intact, any
        // present target (matching or not) is foreign, and an absent target
        // proves the effect never happened.
        if target_absent {
            retire_through_no_mutation(store, &handle, phase)?;
            return Ok(XfrmSaRelocationRestartOutcome::NoMutation);
        }
        retire_through_no_mutation(store, &handle, phase)?;
        return Ok(XfrmSaRelocationRestartOutcome::ForeignUntouched);
    }
    if old_absent {
        if target_relocated {
            let admitted = store.transition(
                &handle,
                phase,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                None,
            )?;
            return retire_admitted(store, admitted, removal, backend).await;
        }
        if target_absent {
            publish_state_absent(store, &handle, phase)?;
            return Ok(XfrmSaRelocationRestartOutcome::StateAbsent);
        }
        retire_through_no_mutation(store, &handle, phase)?;
        return Ok(XfrmSaRelocationRestartOutcome::ForeignUntouched);
    }
    // A present old identity that does not match the bound current identity
    // is foreign regardless of the target.
    retire_through_no_mutation(store, &handle, phase)?;
    Ok(XfrmSaRelocationRestartOutcome::ForeignUntouched)
}

fn retire_through_no_mutation(
    store: &XfrmSaRelocationRecoveryStore,
    handle: &XfrmSaRelocationRecoveryHandle,
    phase: XfrmSaRelocationDurablePhase,
) -> Result<(), XfrmSaRelocationDurableError> {
    let no_mutation = store.transition(
        handle,
        phase,
        XfrmSaRelocationDurablePhase::NoMutation,
        None,
    )?;
    store.transition(
        &store.handle_for_record(&no_mutation)?,
        XfrmSaRelocationDurablePhase::NoMutation,
        XfrmSaRelocationDurablePhase::Retired,
        None,
    )?;
    Ok(())
}

fn publish_state_absent(
    store: &XfrmSaRelocationRecoveryStore,
    handle: &XfrmSaRelocationRecoveryHandle,
    phase: XfrmSaRelocationDurablePhase,
) -> Result<(), XfrmSaRelocationDurableError> {
    store.transition(
        handle,
        phase,
        XfrmSaRelocationDurablePhase::StateAbsent,
        None,
    )?;
    Ok(())
}

async fn retire_admitted<B>(
    store: &XfrmSaRelocationRecoveryStore,
    admitted: DurableRelocationRecord,
    removal: &RemoveSaRequest,
    backend: &B,
) -> Result<XfrmSaRelocationRestartOutcome, XfrmSaRelocationDurableError>
where
    B: XfrmBackend + ?Sized,
{
    match backend.remove_sa(*removal).await {
        Ok(()) | Err(XfrmError::NotFound) => {
            store.transition(
                &store.handle_for_record(&admitted)?,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmSaRelocationRestartOutcome::OwnedResidueRetired)
        }
        Err(source) => Ok(XfrmSaRelocationRestartOutcome::RemovalPending { source }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, DirBuilder},
        io,
        os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf},
    };

    use crate::{
        InstallSaRequest, IpAddress, LifetimeConfig, MockOperation, MockXfrmBackend,
        QuerySaRequest, SaParameters, SaRelocationDirection, SaRelocationEncap,
        SaRelocationIdentity, UdpEncap, XfrmBackend, XfrmError, XfrmId, XfrmLookupMark, XfrmMode,
        XfrmRequestId, XfrmSelector,
    };

    use super::*;
    use crate::durable_relocation::{
        XfrmSaRelocationRecoveryProofKey, XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES,
    };

    const NAMESPACE_BINDING: [u8; 40] = [0xa6; 40];
    const PROOF_KEY_BYTE: u8 = 0x92;
    const TEST_SPI: u32 = 0x6290_0001;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            for _ in 0..8 {
                let identity = XfrmSaRelocationOperationId::generate().unwrap();
                let name = identity
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let path =
                    std::env::temp_dir().join(format!("opc-xfrm-durable-relocation-flow-{name}"));
                assert!(path.is_absolute());
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("failed to create secure test root: {error}"),
                }
            }
            panic!("failed to allocate a unique secure test root");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn proof_key() -> XfrmSaRelocationRecoveryProofKey {
        XfrmSaRelocationRecoveryProofKey::new([PROOF_KEY_BYTE; 32]).unwrap()
    }

    fn open_store(root: &TestRoot) -> XfrmSaRelocationRecoveryStore {
        XfrmSaRelocationRecoveryStore::open_bound(root.path(), proof_key(), NAMESPACE_BINDING)
            .unwrap()
    }

    fn operation(byte: u8) -> XfrmSaRelocationOperationId {
        XfrmSaRelocationOperationId::from_bytes([byte; 16]).unwrap()
    }

    fn generation(value: u64) -> XfrmSaRelocationOperationGeneration {
        XfrmSaRelocationOperationGeneration::new(value).unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn old_destination() -> IpAddress {
        ipv4(192, 0, 2, 62)
    }

    fn new_destination() -> IpAddress {
        ipv4(198, 51, 100, 20)
    }

    fn old_source() -> IpAddress {
        ipv4(192, 0, 2, 61)
    }

    fn new_source() -> IpAddress {
        ipv4(198, 51, 100, 10)
    }

    fn foreign_source() -> IpAddress {
        ipv4(203, 0, 113, 7)
    }

    fn current_encap() -> Option<UdpEncap> {
        Some(UdpEncap::esp_in_udp(4500, 4500))
    }

    fn relocated_encap() -> UdpEncap {
        UdpEncap::esp_in_udp(4500, 62_000)
    }

    fn lookup_mark() -> Option<XfrmLookupMark> {
        Some(XfrmLookupMark::full(0x6290))
    }

    fn seed_parameters(
        destination: IpAddress,
        source: IpAddress,
        encap: Option<UdpEncap>,
    ) -> SaParameters {
        SaParameters {
            selector: XfrmSelector::new(ipv4(10, 62, 9, 1), ipv4(10, 62, 9, 2), 17),
            id: XfrmId {
                destination,
                spi: TEST_SPI,
                protocol: 50,
            },
            source_address: source,
            request_id: XfrmRequestId::new(629),
            auth: None,
            crypt: None,
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
            replay_state: None,
            encap,
            mark: lookup_mark(),
            output_mark: None,
            if_id: Some(9),
            egress_dscp: None,
        }
    }

    fn query_at(destination: IpAddress) -> QuerySaRequest {
        let mut query = QuerySaRequest::new(destination, 50, TEST_SPI);
        if let Some(mark) = lookup_mark() {
            query = query.with_mark(mark);
        }
        query
    }

    async fn install_at(
        backend: &MockXfrmBackend,
        destination: IpAddress,
        source: IpAddress,
        encap: Option<UdpEncap>,
    ) {
        backend
            .install_sa(InstallSaRequest {
                parameters: seed_parameters(destination, source, encap),
            })
            .await
            .unwrap();
    }

    /// Seed the current SA and build a request against its exact identity.
    /// `same_identity` selects an encapsulation/source-only relocation whose
    /// target XfrmId equals the current one.
    async fn seeded_request(
        backend: &MockXfrmBackend,
        direction: SaRelocationDirection,
        same_identity: bool,
    ) -> RelocateSaRequest {
        seeded_request_with_encap(
            backend,
            direction,
            same_identity,
            SaRelocationEncap::Set(relocated_encap()),
        )
        .await
    }

    /// Like [`seeded_request`], with an explicit encapsulation action (used
    /// for the NAT-T removal rows, where the current encapsulation is present
    /// and the resulting encapsulation is none).
    async fn seeded_request_with_encap(
        backend: &MockXfrmBackend,
        direction: SaRelocationDirection,
        same_identity: bool,
        encap: SaRelocationEncap,
    ) -> RelocateSaRequest {
        install_at(backend, old_destination(), old_source(), current_encap()).await;
        let current = backend
            .query_sa_relocation_identity(query_at(old_destination()))
            .await
            .unwrap();
        let new_destination = if same_identity {
            old_destination()
        } else {
            new_destination()
        };
        RelocateSaRequest {
            current,
            new_source_address: new_source(),
            new_destination,
            encap,
            direction,
        }
    }

    async fn assert_identity(
        backend: &MockXfrmBackend,
        destination: IpAddress,
        source: IpAddress,
        encap: Option<UdpEncap>,
    ) {
        let observed = backend
            .query_sa_relocation_identity(query_at(destination))
            .await
            .unwrap();
        let parameters = seed_parameters(destination, source, encap);
        let expected = SaRelocationIdentity {
            selector: crate::SaRelocationSelector::from_selector(&parameters.selector),
            id: XfrmId {
                destination,
                spi: TEST_SPI,
                protocol: 50,
            },
            source_address: source,
            request_id: XfrmRequestId::new(629),
            mode: XfrmMode::Tunnel,
            encap,
            mark: lookup_mark(),
            if_id: Some(9),
            output_mark: None,
        };
        assert_eq!(observed, expected);
    }

    async fn assert_absent(backend: &MockXfrmBackend, destination: IpAddress) {
        assert!(matches!(
            backend
                .query_sa_relocation_identity(query_at(destination))
                .await,
            Err(XfrmError::NotFound)
        ));
    }

    fn assert_no_removal(backend: &MockXfrmBackend) {
        assert!(backend
            .operations()
            .iter()
            .all(|operation| !matches!(operation, MockOperation::RemoveSa { .. })));
    }

    fn removal_count(backend: &MockXfrmBackend) -> usize {
        backend
            .operations()
            .iter()
            .filter(|operation| matches!(operation, MockOperation::RemoveSa { .. }))
            .count()
    }

    async fn prepare_and_issue(
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        request: &RelocateSaRequest,
        backend: &MockXfrmBackend,
    ) -> Result<XfrmSaRelocationDurableOutcome, XfrmSaRelocationDurableError> {
        let prepared =
            prepare_durable_sa_relocation(store, operation_id, operation_generation, request)?;
        let proof = witness_sa_relocation_pre_effect_proof(backend, request)
            .await
            .map_err(|_| XfrmSaRelocationDurableError::InvalidTransition)?;
        issue_durable_sa_relocation(
            store,
            &prepared,
            operation_id,
            operation_generation,
            request,
            backend,
            proof,
        )
        .await
    }

    async fn issuing_cut(
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        request: &RelocateSaRequest,
        backend: &MockXfrmBackend,
        admit_backend_effect: bool,
    ) {
        let prepared =
            prepare_durable_sa_relocation(store, operation_id, operation_generation, request)
                .unwrap();
        let proof = if request.new_destination == request.current.id.destination {
            XfrmSaRelocationPreEffectProof::SameIdentityWitnessed
        } else {
            XfrmSaRelocationPreEffectProof::TargetAbsent
        };
        cut_durable_sa_relocation_at_issuing(
            store,
            &prepared,
            operation_id,
            operation_generation,
            request,
            backend,
            proof,
            admit_backend_effect,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_run_publishes_relocated_proof_and_recovers_idempotently() {
        for direction in [
            SaRelocationDirection::Inbound,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        ] {
            for same_identity in [false, true] {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, same_identity).await;
                let operation_id = operation(if same_identity { 0x11 } else { 0x10 });
                let operation_generation = generation(1);
                let store = open_store(&root);

                let outcome = prepare_and_issue(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap();
                assert_eq!(outcome.as_str(), "relocated");
                assert_eq!(backend.relocations().len(), 1);
                assert_identity(
                    &backend,
                    request.new_destination,
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
                if !same_identity {
                    assert_absent(&backend, old_destination()).await;
                }

                drop(store);
                backend.clear_operations();
                let reopened = open_store(&root);
                for _ in 0..2 {
                    assert_eq!(
                        recover_durable_sa_relocation(
                            &reopened,
                            operation_id,
                            operation_generation,
                            &request,
                            &backend,
                        )
                        .await
                        .unwrap()
                        .as_str(),
                        "relocated"
                    );
                    assert_no_removal(&backend);
                }
                // Terminal proof never authorizes deleting the relocated SA.
                assert_identity(
                    &backend,
                    request.new_destination,
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn deterministic_effect_failure_becomes_no_mutation_and_retires() {
        for direction in [
            SaRelocationDirection::Inbound,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        ] {
            for same_identity in [false, true] {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, same_identity).await;
                let operation_id = operation(if same_identity { 0x21 } else { 0x20 });
                let operation_generation = generation(2);
                let store = open_store(&root);
                let prepared = prepare_durable_sa_relocation(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                )
                .unwrap();
                let proof = witness_sa_relocation_pre_effect_proof(&backend, &request)
                    .await
                    .unwrap();
                // A deterministic non-indeterminate backend failure is
                // provably no mutation.
                backend.set_failure(XfrmError::Unavailable);
                let outcome = issue_durable_sa_relocation(
                    &store,
                    &prepared,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                    proof,
                )
                .await
                .unwrap();
                assert_eq!(outcome.as_str(), "no_mutation");
                backend.clear_failure();

                drop(store);
                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        operation_generation,
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "no_mutation"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
            }
        }
    }

    #[tokio::test]
    async fn indeterminate_effect_keeps_record_gating_until_reconciled() {
        for direction in [
            SaRelocationDirection::Inbound,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        ] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, direction, false).await;
            let operation_id = operation(0x30);
            let operation_generation = generation(3);
            let store = open_store(&root);
            let prepared =
                prepare_durable_sa_relocation(&store, operation_id, operation_generation, &request)
                    .unwrap();
            let proof = witness_sa_relocation_pre_effect_proof(&backend, &request)
                .await
                .unwrap();
            backend.set_failure(XfrmError::StateIndeterminate {
                operation: "relocate_sa_mock_mutation",
            });
            let outcome = issue_durable_sa_relocation(
                &store,
                &prepared,
                operation_id,
                operation_generation,
                &request,
                &backend,
                proof,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "indeterminate");
            assert!(matches!(
                outcome.source(),
                Some(XfrmError::StateIndeterminate { .. })
            ));
            // The unresolved record gates cooperating writers.
            assert!(store.has_unresolved_writer_authority().unwrap());
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmSaRelocationDurableError::InvalidTransition)
            );

            // Recovery with a still-failing readback stays indeterminate and
            // keeps the record gating.
            assert_eq!(
                recover_durable_sa_relocation(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "indeterminate"
            );
            assert!(store.has_unresolved_writer_authority().unwrap());

            // Once readback works again, the intact old identity plus absent
            // target converge the record as no-mutation.
            backend.clear_failure();
            backend.clear_operations();
            assert_eq!(
                recover_durable_sa_relocation(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "no_mutation"
            );
            assert_no_removal(&backend);
            assert!(store.advance_writer_epoch().is_ok());
        }
    }

    #[tokio::test]
    async fn classification_table_for_identity_change_relocations() {
        // Every verdict row of the different-identity table, across both
        // directions.
        for direction in [
            SaRelocationDirection::Inbound,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        ] {
            // intact old + absent target: the effect provably never happened.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x40);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    false,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "no_mutation"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
                // Reinstall-after-no-mutation proof: the old identity was
                // never removed.
                assert!(matches!(
                    install_at_check(&backend).await,
                    Err(XfrmError::AlreadyExists)
                ));
            }

            // absent old + TARGET-RELOCATED: the move happened and was never
            // published; the exact target residue is retired.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x41);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    true,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "owned_residue_retired"
                );
                assert_eq!(removal_count(&backend), 1);
                assert_absent(&backend, new_destination()).await;
                assert_absent(&backend, old_destination()).await;
                // Reinstall after delete succeeds, and repeat recovery is
                // idempotent without re-deleting.
                install_at(
                    &backend,
                    new_destination(),
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "retired"
                );
                assert_no_removal(&backend);
                assert_identity(
                    &backend,
                    new_destination(),
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
            }

            // intact old + present target (any): an atomic move cannot
            // duplicate, so the target is foreign.
            for target_matches_expectation in [true, false] {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x42);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    false,
                )
                .await;
                let target_source = if target_matches_expectation {
                    new_source()
                } else {
                    foreign_source()
                };
                let target_encap = if target_matches_expectation {
                    Some(relocated_encap())
                } else {
                    current_encap()
                };
                install_at(&backend, new_destination(), target_source, target_encap).await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "foreign_untouched"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
                assert_identity(&backend, new_destination(), target_source, target_encap).await;
            }

            // absent old + foreign target: foreign state stays untouched.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x43);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    true,
                )
                .await;
                // Replace the owned residue with a foreign same-identity SA.
                backend
                    .remove_sa(exact_removal_request(&request))
                    .await
                    .unwrap();
                install_at(
                    &backend,
                    new_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "foreign_untouched"
                );
                assert_no_removal(&backend);
                assert_identity(
                    &backend,
                    new_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
            }

            // absent old + absent target: foreign removal or expiry.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x44);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    true,
                )
                .await;
                backend
                    .remove_sa(exact_removal_request(&request))
                    .await
                    .unwrap();
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "state_absent"
                );
                assert_no_removal(&backend);
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "state_absent"
                );
                assert_no_removal(&backend);
            }

            // FOREIGN old identity: foreign regardless of the target.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x45);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    false,
                )
                .await;
                // Replace the old identity with foreign state before recovery.
                backend
                    .remove_sa(RemoveSaRequest {
                        destination: old_destination(),
                        protocol: 50,
                        spi: TEST_SPI,
                        mark: lookup_mark(),
                    })
                    .await
                    .unwrap();
                install_at(
                    &backend,
                    old_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "foreign_untouched"
                );
                assert_no_removal(&backend);
                assert_identity(
                    &backend,
                    old_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
            }

            // unreadable readback: retryable indeterminate, kept gating.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, false).await;
                let operation_id = operation(0x46);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(4),
                    &request,
                    &backend,
                    false,
                )
                .await;
                backend.set_failure(XfrmError::Unavailable);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &store,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "indeterminate"
                );
                assert!(store.has_unresolved_writer_authority().unwrap());
                backend.clear_failure();
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &store,
                        operation_id,
                        generation(4),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "no_mutation"
                );
                assert_no_removal(&backend);
            }
        }
    }

    async fn install_at_check(backend: &MockXfrmBackend) -> Result<(), XfrmError> {
        backend
            .install_sa(InstallSaRequest {
                parameters: seed_parameters(old_destination(), old_source(), current_encap()),
            })
            .await
    }

    #[tokio::test]
    async fn classification_table_for_same_identity_relocations() {
        for direction in [
            SaRelocationDirection::Inbound,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        ] {
            // Matches bound current: the effect never happened.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, true).await;
                let operation_id = operation(0x50);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    false,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "no_mutation"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
            }

            // Matches the relocation expectation: the encap/source change
            // happened and is retired through the exact same identity.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, true).await;
                let operation_id = operation(0x51);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    true,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "owned_residue_retired"
                );
                assert_eq!(removal_count(&backend), 1);
                assert_absent(&backend, old_destination()).await;
                // Reinstall after delete succeeds; repeat recovery is
                // idempotent and never re-deletes.
                install_at(
                    &backend,
                    old_destination(),
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "retired"
                );
                assert_no_removal(&backend);
                assert_identity(
                    &backend,
                    old_destination(),
                    new_source(),
                    Some(relocated_encap()),
                )
                .await;
            }

            // Matches neither: foreign state at the shared identity.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, true).await;
                let operation_id = operation(0x52);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    false,
                )
                .await;
                backend
                    .remove_sa(exact_removal_request(&request))
                    .await
                    .unwrap();
                install_at(
                    &backend,
                    old_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "foreign_untouched"
                );
                assert_no_removal(&backend);
                assert_identity(
                    &backend,
                    old_destination(),
                    foreign_source(),
                    current_encap(),
                )
                .await;
            }

            // Absent shared identity: foreign removal or expiry.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request = seeded_request(&backend, direction, true).await;
                let operation_id = operation(0x53);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    false,
                )
                .await;
                backend
                    .remove_sa(exact_removal_request(&request))
                    .await
                    .unwrap();
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "state_absent"
                );
                assert_no_removal(&backend);
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "state_absent"
                );
                assert_no_removal(&backend);
            }

            // NAT-T removal (current encapsulation present, resulting
            // encapsulation none): the shared identity still matches the
            // bound current, so the effect never happened.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request =
                    seeded_request_with_encap(&backend, direction, true, SaRelocationEncap::Remove)
                        .await;
                let operation_id = operation(0x54);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    false,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "no_mutation"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
            }

            // NAT-T removal whose encap/source change happened: the shared
            // identity matches the relocation expectation (native ESP at the
            // new source) and is retired through the exact same identity.
            {
                let root = TestRoot::new();
                let backend = MockXfrmBackend::new();
                let request =
                    seeded_request_with_encap(&backend, direction, true, SaRelocationEncap::Remove)
                        .await;
                let operation_id = operation(0x55);
                let store = open_store(&root);
                issuing_cut(
                    &store,
                    operation_id,
                    generation(5),
                    &request,
                    &backend,
                    true,
                )
                .await;
                drop(store);

                backend.clear_operations();
                let reopened = open_store(&root);
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "owned_residue_retired"
                );
                assert_eq!(removal_count(&backend), 1);
                assert_absent(&backend, old_destination()).await;
                // Reinstall after delete succeeds as native ESP; repeat
                // recovery is idempotent and never re-deletes.
                install_at(&backend, old_destination(), new_source(), None).await;
                backend.clear_operations();
                assert_eq!(
                    recover_durable_sa_relocation(
                        &reopened,
                        operation_id,
                        generation(5),
                        &request,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "retired"
                );
                assert_no_removal(&backend);
                assert_identity(&backend, old_destination(), new_source(), None).await;
            }
        }
    }

    #[tokio::test]
    async fn crash_after_prepare_never_deletes_and_reopens_the_gate() {
        for same_identity in [false, true] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let request =
                seeded_request(&backend, SaRelocationDirection::Inbound, same_identity).await;
            let operation_id = operation(if same_identity { 0x61 } else { 0x60 });
            let store = open_store(&root);
            prepare_durable_sa_relocation(&store, operation_id, generation(6), &request).unwrap();
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            // Prepared gates the store until recovery retires it.
            assert!(reopened.has_unresolved_writer_authority().unwrap());
            assert_eq!(
                reopened.advance_writer_epoch(),
                Err(XfrmSaRelocationDurableError::InvalidTransition)
            );
            assert_eq!(
                recover_durable_sa_relocation(
                    &reopened,
                    operation_id,
                    generation(6),
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "no_mutation"
            );
            assert_no_removal(&backend);
            assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
            // Recovery reopened the gate for epoch advances and new operations.
            assert!(reopened.advance_writer_epoch().is_ok());
            assert!(!reopened.has_unresolved_writer_authority().unwrap());
            assert!(prepare_durable_sa_relocation(
                &reopened,
                operation(0x6f),
                generation(6),
                &request,
            )
            .is_ok());
        }
    }

    #[tokio::test]
    async fn unresolved_relocation_gates_a_second_operation_until_recovered() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request_a = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
        let operation_a = operation(0x70);
        let store = open_store(&root);
        issuing_cut(
            &store,
            operation_a,
            generation(7),
            &request_a,
            &backend,
            false,
        )
        .await;

        // A distinct operation repeating the active deletion identity reports
        // the duplicate even while the first record gates preparation.
        assert_eq!(
            prepare_durable_sa_relocation(&store, operation(0x71), generation(7), &request_a),
            Err(XfrmSaRelocationDurableError::Duplicate)
        );
        // A distinct operation with a distinct deletion identity fails at the
        // unresolved-record gate instead, and ordinary epoch advances are
        // fenced too.
        let mut distinct_request = request_a.clone();
        distinct_request.new_destination = ipv4(198, 51, 100, 21);
        assert_eq!(
            prepare_durable_sa_relocation(
                &store,
                operation(0x71),
                generation(7),
                &distinct_request
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );

        // Recovery retires the first operation and reopens the gate; the
        // second operation then converges independently.
        assert_eq!(
            recover_durable_sa_relocation(
                &store,
                operation_a,
                generation(7),
                &request_a,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "no_mutation"
        );
        let request_b = seeded_request_for(
            &backend,
            SaRelocationDirection::OutboundBlockPolicyInstalled,
        )
        .await;
        let outcome =
            prepare_and_issue(&store, operation(0x71), generation(7), &request_b, &backend)
                .await
                .unwrap();
        assert_eq!(outcome.as_str(), "relocated");
    }

    /// Seed a second identity so a second operation can run after the first
    /// retired: reuses the fixture addresses with a fresh SA at the current
    /// identity.
    async fn seeded_request_for(
        backend: &MockXfrmBackend,
        direction: SaRelocationDirection,
    ) -> RelocateSaRequest {
        let current = backend
            .query_sa_relocation_identity(query_at(old_destination()))
            .await
            .unwrap();
        RelocateSaRequest {
            current,
            new_source_address: new_source(),
            new_destination: new_destination(),
            encap: SaRelocationEncap::Set(relocated_encap()),
            direction,
        }
    }

    #[tokio::test]
    async fn removal_failure_is_durable_and_retryable_after_restart() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
        let operation_id = operation(0x80);
        let store = open_store(&root);
        issuing_cut(
            &store,
            operation_id,
            generation(8),
            &request,
            &backend,
            true,
        )
        .await;

        // Reconciliation admitted the owned residue through the Issuing entry
        // edge; the process then dies during the durable deletion.
        let record = store
            .restore(
                operation_id,
                generation(8),
                fingerprints_for(&store, &request),
            )
            .unwrap();
        let admitted = store
            .transition(
                &store.handle_for_record(&record).unwrap(),
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                None,
            )
            .unwrap();
        assert_eq!(
            admitted.pre_effect_proof,
            Some(XfrmSaRelocationPreEffectProof::TargetAbsent)
        );
        backend.set_failure(XfrmError::Unavailable);
        let first =
            recover_durable_sa_relocation(&store, operation_id, generation(8), &request, &backend)
                .await
                .unwrap();
        assert_eq!(first.as_str(), "removal_pending");
        assert!(matches!(first.source(), Some(XfrmError::Unavailable)));
        // The RemovalAdmitted record keeps gating until the removal retries.
        assert!(store.has_unresolved_writer_authority().unwrap());
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        drop(store);

        backend.clear_failure();
        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_sa_relocation(
                &reopened,
                operation_id,
                generation(8),
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
        assert_absent(&backend, request.new_destination).await;
    }

    fn fingerprints_for(
        store: &XfrmSaRelocationRecoveryStore,
        request: &RelocateSaRequest,
    ) -> crate::durable_relocation::DurableRelocationFingerprints {
        store.fingerprints_for_request(request).unwrap()
    }

    #[tokio::test]
    async fn proof_request_inconsistency_recovers_repair_required() {
        // A same-identity request whose record carries `TargetAbsent` (or the
        // reverse) fails closed without deletion and keeps gating.
        for (same_identity, wrong_proof) in [
            (true, XfrmSaRelocationPreEffectProof::TargetAbsent),
            (false, XfrmSaRelocationPreEffectProof::SameIdentityWitnessed),
        ] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let request =
                seeded_request(&backend, SaRelocationDirection::Inbound, same_identity).await;
            let operation_id = operation(if same_identity { 0x91 } else { 0x90 });
            let store = open_store(&root);
            let prepared =
                prepare_durable_sa_relocation(&store, operation_id, generation(9), &request)
                    .unwrap();
            // The store is deliberately request-agnostic: it accepts either
            // proof at `Prepared -> Issuing`. Recovery validates consistency.
            store
                .transition(
                    &prepared,
                    XfrmSaRelocationDurablePhase::Prepared,
                    XfrmSaRelocationDurablePhase::Issuing,
                    Some(wrong_proof),
                )
                .unwrap();

            backend.clear_operations();
            assert_eq!(
                recover_durable_sa_relocation(
                    &store,
                    operation_id,
                    generation(9),
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "repair_required"
            );
            assert_no_removal(&backend);
            // The inconsistent record keeps gating cooperating writers.
            assert!(store.has_unresolved_writer_authority().unwrap());
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmSaRelocationDurableError::InvalidTransition)
            );
            assert_identity(&backend, old_destination(), old_source(), current_encap()).await;
        }
    }

    #[tokio::test]
    async fn pre_effect_witness_rules_match_the_run_contract() {
        fn current_removal() -> RemoveSaRequest {
            RemoveSaRequest {
                destination: old_destination(),
                protocol: 50,
                spi: TEST_SPI,
                mark: lookup_mark(),
            }
        }

        // Absent old identity: deterministic current-state mismatch.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
            backend.remove_sa(current_removal()).await.unwrap();
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch)
            ));
        }
        // Mismatching old identity: deterministic current-state mismatch.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
            // Replace the seeded SA with foreign state at the same identity.
            backend.remove_sa(current_removal()).await.unwrap();
            install_at(
                &backend,
                old_destination(),
                foreign_source(),
                current_encap(),
            )
            .await;
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch)
            ));
        }
        // Present distinct target: deterministic conflict.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
            install_at(
                &backend,
                new_destination(),
                foreign_source(),
                current_encap(),
            )
            .await;
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Err(XfrmSaRelocationPreEffectRejection::TargetConflict)
            ));
        }
        // Unreadable readback: retryable rejection.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
            backend.set_failure(XfrmError::Unavailable);
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Err(XfrmSaRelocationPreEffectRejection::ReadbackFailed(
                    XfrmError::Unavailable
                ))
            ));
        }
        // Same-identity witness needs no target readback.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, true).await;
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Ok(XfrmSaRelocationPreEffectProof::SameIdentityWitnessed)
            ));
            assert_absent(&backend, new_destination()).await;
        }
        // Different-identity witness proves the target absent.
        {
            let backend = MockXfrmBackend::new();
            let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
            assert!(matches!(
                witness_sa_relocation_pre_effect_proof(&backend, &request).await,
                Ok(XfrmSaRelocationPreEffectProof::TargetAbsent)
            ));
        }
    }

    #[tokio::test]
    async fn fail_closed_admission_validation_never_reaches_the_backend() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
        let operation_id = operation(0xa0);
        let operation_generation = generation(10);
        let store = open_store(&root);
        let prepared =
            prepare_durable_sa_relocation(&store, operation_id, operation_generation, &request)
                .unwrap();
        backend.clear_operations();

        // Wrong request fingerprint.
        let mut wrong_request = request.clone();
        wrong_request.new_source_address = foreign_source();
        assert_eq!(
            validate_durable_sa_relocation_admission(
                &store,
                &prepared,
                operation_id,
                operation_generation,
                &wrong_request,
            ),
            Err(XfrmSaRelocationDurableError::WrongBinding)
        );
        // Wrong correlation.
        assert_eq!(
            validate_durable_sa_relocation_admission(
                &store,
                &prepared,
                operation(0xa1),
                operation_generation,
                &request,
            ),
            Err(XfrmSaRelocationDurableError::WrongBinding)
        );
        // Wrong generation.
        assert_eq!(
            validate_durable_sa_relocation_admission(
                &store,
                &prepared,
                operation_id,
                generation(11),
                &request,
            ),
            Err(XfrmSaRelocationDurableError::WrongBinding)
        );
        // Tampered handle bytes.
        let mut encoded = prepared.to_bytes();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        let tampered = XfrmSaRelocationRecoveryHandle::from_bytes(encoded);
        assert_eq!(
            validate_durable_sa_relocation_admission(
                &store,
                &tampered,
                operation_id,
                operation_generation,
                &request,
            ),
            Err(XfrmSaRelocationDurableError::AuthenticationFailed)
        );
        // Replayed handle after a transition is stale.
        let proof = witness_sa_relocation_pre_effect_proof(&backend, &request)
            .await
            .unwrap();
        issue_durable_sa_relocation(
            &store,
            &prepared,
            operation_id,
            operation_generation,
            &request,
            &backend,
            proof,
        )
        .await
        .unwrap();
        assert_eq!(
            validate_durable_sa_relocation_admission(
                &store,
                &prepared,
                operation_id,
                operation_generation,
                &request,
            ),
            Err(XfrmSaRelocationDurableError::Stale)
        );
        // Only the admitted effect reached the backend.
        assert_eq!(backend.relocations().len(), 1);
    }

    #[tokio::test]
    async fn preparation_reports_narrow_marks_and_malformed_requests_distinctly() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let mut request = seeded_request(&backend, SaRelocationDirection::Inbound, false).await;
        request.current.mark = Some(XfrmLookupMark::new(0x6290_0000, 0xffff_0000).unwrap());
        let store = open_store(&root);
        backend.clear_operations();
        // A narrow lookup mark cannot produce an exact removal identity.
        assert!(matches!(
            prepare_durable_sa_relocation(&store, operation(0xb0), generation(11), &request),
            Err(XfrmSaRelocationDurableError::NonExactRemovalIdentity)
        ));
        // A no-op request (nothing changes) is malformed.
        let mut no_op = request.clone();
        no_op.current.mark = Some(XfrmLookupMark::full(0x6290));
        no_op.new_source_address = no_op.current.source_address;
        no_op.new_destination = no_op.current.id.destination;
        no_op.encap = SaRelocationEncap::Preserve;
        assert!(matches!(
            prepare_durable_sa_relocation(&store, operation(0xb1), generation(11), &no_op),
            Err(XfrmSaRelocationDurableError::Malformed)
        ));
        assert!(backend.operations().is_empty());
        assert!(backend.relocations().is_empty());
    }

    #[test]
    fn restart_outcome_labels_and_diagnostics_are_value_free() {
        for (outcome, label) in [
            (XfrmSaRelocationRestartOutcome::NoMutation, "no_mutation"),
            (XfrmSaRelocationRestartOutcome::StateAbsent, "state_absent"),
            (XfrmSaRelocationRestartOutcome::Relocated, "relocated"),
            (
                XfrmSaRelocationRestartOutcome::OwnedResidueRetired,
                "owned_residue_retired",
            ),
            (
                XfrmSaRelocationRestartOutcome::ForeignUntouched,
                "foreign_untouched",
            ),
            (
                XfrmSaRelocationRestartOutcome::Indeterminate,
                "indeterminate",
            ),
            (
                XfrmSaRelocationRestartOutcome::RepairRequired,
                "repair_required",
            ),
            (XfrmSaRelocationRestartOutcome::Retired, "retired"),
        ] {
            assert_eq!(outcome.as_str(), label);
            let debug = format!("{outcome:?}");
            assert!(debug.contains(label), "debug must carry only the label");
        }
        // Diagnostics must not leak identity material.
        let rendered = format!(
            "{:?} {:?} {:?} {:?}",
            XfrmSaRelocationRestartOutcome::ForeignUntouched,
            XfrmSaRelocationRestartOutcome::RepairRequired,
            XfrmSaRelocationDurableOutcome::Relocated(XfrmSaRelocationRecoveryHandle::from_bytes(
                [0x5a; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES]
            )),
            XfrmSaRelocationPreEffectProof::TargetAbsent,
        );
        // The module fixtures carry addresses, a mark, and encapsulation
        // ports; no diagnostic may leak them.
        for leaked in ["192.0", "198.51", "6290", "0x6290", "5a5a", "4500", "62000"] {
            assert!(!rendered.contains(leaked), "diagnostic leaked {leaked}");
        }
    }
}
