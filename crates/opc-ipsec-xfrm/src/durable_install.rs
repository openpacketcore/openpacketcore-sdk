//! Namespace-serialized durable staged-object install protocol.

use std::fmt;

use crate::durable_object::{
    DurableObjectRecord, XfrmObjectInstallDurableError, XfrmObjectInstallDurablePhase,
    XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
    XfrmObjectInstallPreEffectProof, XfrmObjectInstallRecoveryHandle,
    XfrmObjectInstallRecoveryStore,
};
use crate::{
    ExactRemovePolicyRequest, QueryPolicyRequest, QuerySaRequest, XfrmBackend, XfrmError,
    XfrmObjectInstallRequest, XfrmObjectRemovalRequest,
};

/// Durable terminal result of one create-exclusive staged-object install.
///
/// Every variant carries an authenticated opaque handle. The handle is only
/// correlation data until the same bound store authenticates its current
/// record; its `Debug` and `Display` forms never expose identity material.
#[non_exhaustive]
pub enum XfrmObjectInstallDurableOutcome {
    /// The backend acknowledged acquisition and durable cleanup authority was
    /// published before this result became visible.
    Acquired(XfrmObjectInstallRecoveryHandle),
    /// A pre-effect conflict or `AlreadyExists` definitively proved that this
    /// request made no mutation.
    NoMutation(XfrmObjectInstallRecoveryHandle),
    /// The live install result alone cannot prove ownership. The record and
    /// its durable pre-effect proof remain unresolved so restart recovery can
    /// reconcile them with fresh exact readback under the writer gate. Only a
    /// witnessed pre-effect absence followed by exact presence may establish
    /// owned residue and authorize admitted deletion. A live call carries its
    /// value-free backend failure; a restored record has no recoverable source
    /// value.
    Indeterminate {
        /// Authenticated correlation handle for the fail-closed record.
        handle: XfrmObjectInstallRecoveryHandle,
        /// Observed redaction-safe backend result, when this process saw it.
        source: Option<XfrmError>,
    },
}

impl XfrmObjectInstallDurableOutcome {
    /// Stable, value-free outcome label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Acquired(_) => "acquired",
            Self::NoMutation(_) => "no_mutation",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }

    /// Authenticated opaque correlation handle.
    pub const fn handle(&self) -> &XfrmObjectInstallRecoveryHandle {
        match self {
            Self::Acquired(handle) | Self::NoMutation(handle) => handle,
            Self::Indeterminate { handle, .. } => handle,
        }
    }

    /// Redaction-safe backend failure observed by the current process.
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::Indeterminate { source, .. } => source.as_ref(),
            Self::Acquired(_) | Self::NoMutation(_) => None,
        }
    }
}

impl fmt::Debug for XfrmObjectInstallDurableOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectInstallDurableOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

/// Deterministic disposition of a durable record after process loss.
#[non_exhaustive]
pub enum XfrmObjectInstallRestartOutcome {
    /// A prepared or explicit no-mutation record was retired without a
    /// backend removal.
    NoMutation,
    /// Exact owned residue was absent or removed and the record was retired.
    OwnedResidueRetired,
    /// The operation may have mutated state, but no authenticated acquisition
    /// was durably published. No deletion was attempted.
    Indeterminate,
    /// Product ownership was already committed; cleanup is forbidden.
    Committed,
    /// Cleanup had already completed.
    Retired,
    /// Exact removal failed after `RemovalAdmitted` was made durable. The
    /// record remains retryable and blocks a cooperating replacement.
    RemovalPending {
        /// Redaction-safe backend failure.
        source: XfrmError,
    },
    /// A pre-effect proof witnessed the exact identity already present, so no
    /// install effect was admitted, and that same foreign/conflicting identity
    /// is still present. The record was retired without any deletion; the
    /// foreign state was left untouched.
    ForeignUntouched,
    /// The durable record is inconsistent in a way this boundary cannot safely
    /// repair (for example a stale writer epoch or a missing proof). The record
    /// is retained and continues to gate cooperating writers; product repair is
    /// required before any deletion may be considered.
    RepairRequired,
}

impl XfrmObjectInstallRestartOutcome {
    /// Stable, value-free recovery label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoMutation => "no_mutation",
            Self::OwnedResidueRetired => "owned_residue_retired",
            Self::Indeterminate => "indeterminate",
            Self::Committed => "committed",
            Self::Retired => "retired",
            Self::RemovalPending { .. } => "removal_pending",
            Self::ForeignUntouched => "foreign_untouched",
            Self::RepairRequired => "repair_required",
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

impl fmt::Debug for XfrmObjectInstallRestartOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectInstallRestartOutcome")
            .field("outcome", &self.as_str())
            .finish_non_exhaustive()
    }
}

pub(crate) fn prepare_durable_object_install(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    store.prepare(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )
}

pub(crate) fn durable_object_install_phase(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    store
        .restore(
            operation_id,
            operation_generation,
            request.object(),
            fingerprints,
        )
        .map(|record| record.phase)
}

pub(crate) fn validate_durable_object_install_admission(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<(), XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore_handle(prepared, request.object(), fingerprints)?;
    if record.operation_id != operation_id
        || record.operation_generation != operation_generation
        || record.phase != XfrmObjectInstallDurablePhase::Prepared
    {
        return Err(XfrmObjectInstallDurableError::WrongBinding);
    }
    Ok(())
}

pub(crate) async fn issue_durable_object_install<B>(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
    pre_effect_proof: XfrmObjectInstallPreEffectProof,
) -> Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    validate_durable_object_install_admission(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
    )?;

    let issuing = store.transition(
        prepared,
        XfrmObjectInstallDurablePhase::Prepared,
        XfrmObjectInstallDurablePhase::Issuing,
        Some(pre_effect_proof),
    )?;
    let (phase, source) = match pre_effect_proof {
        // A conflicting SA can expire autonomously between GETSA and NEWSA.
        // Issuing after witnessing it could therefore acquire the same
        // identity while retaining a Conflict proof, which cannot authorize
        // later cleanup. Resolve the collision without admitting an effect.
        XfrmObjectInstallPreEffectProof::Conflict => {
            (XfrmObjectInstallDurablePhase::NoMutation, None)
        }
        XfrmObjectInstallPreEffectProof::Absent => match install(backend, request).await {
            Ok(()) => (XfrmObjectInstallDurablePhase::Acquired, None),
            Err(XfrmError::AlreadyExists) => (XfrmObjectInstallDurablePhase::NoMutation, None),
            Err(source) => (XfrmObjectInstallDurablePhase::Indeterminate, Some(source)),
        },
    };
    let terminal = store.transition(
        &store.handle_for_record(&issuing)?,
        XfrmObjectInstallDurablePhase::Issuing,
        phase,
        None,
    )?;
    let handle = store.handle_for_record(&terminal)?;
    Ok(match phase {
        XfrmObjectInstallDurablePhase::Acquired => {
            XfrmObjectInstallDurableOutcome::Acquired(handle)
        }
        XfrmObjectInstallDurablePhase::NoMutation => {
            XfrmObjectInstallDurableOutcome::NoMutation(handle)
        }
        XfrmObjectInstallDurablePhase::Indeterminate => {
            XfrmObjectInstallDurableOutcome::Indeterminate { handle, source }
        }
        _ => return Err(XfrmObjectInstallDurableError::InvalidTransition),
    })
}

/// Process-loss detector seam: drive a prepared operation to a durable
/// `Issuing` record and stop before the terminal publication.
///
/// This reproduces the exact crash window that `issue_durable_object_install`
/// would leave if the process died between the `Issuing` publication and the
/// terminal record. When `admit_backend_effect` is true the install is invoked
/// exactly as the real effect admission does (the writer epoch was already
/// burned by the `Issuing` transition), so the kernel object exists while the
/// record remains `Issuing`; when false the backend is never touched. No
/// terminal phase is published, so the record stays unresolved and
/// recoverable. This is only used by privileged crash detectors and never
/// grants deletion authority.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_object_install_at_issuing<B>(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
    pre_effect_proof: XfrmObjectInstallPreEffectProof,
    admit_backend_effect: bool,
) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    if admit_backend_effect && pre_effect_proof != XfrmObjectInstallPreEffectProof::Absent {
        return Err(XfrmObjectInstallDurableError::InvalidTransition);
    }
    validate_durable_object_install_admission(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
    )?;
    let issuing = store.transition(
        prepared,
        XfrmObjectInstallDurablePhase::Prepared,
        XfrmObjectInstallDurablePhase::Issuing,
        Some(pre_effect_proof),
    )?;
    if admit_backend_effect {
        // Simulate the kernel accepting the effect before the terminal record
        // is published. The outcome is intentionally ignored: a crash here
        // leaves no durable terminal result regardless of success.
        let _ = install(backend, request).await;
    }
    store.handle_for_record(&issuing)
}

/// Process-loss detector seam: admit the real install effect and durably
/// publish `Indeterminate`, then stop before recovery can reconcile it.
///
/// This uses the same validation, `Prepared -> Issuing` transition, and
/// backend effect admission as the production run path. It deliberately
/// replaces the successful terminal publication with `Indeterminate`, which
/// models losing an otherwise unknowable backend acknowledgement. The
/// returned handle authenticates the current cut record for privileged
/// restart detectors.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_object_install_at_indeterminate_after_effect<B>(
    store: &XfrmObjectInstallRecoveryStore,
    prepared: &XfrmObjectInstallRecoveryHandle,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
    pre_effect_proof: XfrmObjectInstallPreEffectProof,
) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    // The effect is admitted exactly once by the same cut helper used for the
    // Issuing process-loss detector. A Conflict proof is rejected there,
    // mirroring the production rule that no install may follow a witnessed
    // conflict.
    let issuing = cut_durable_object_install_at_issuing(
        store,
        prepared,
        operation_id,
        operation_generation,
        request,
        backend,
        pre_effect_proof,
        true,
    )
    .await?;
    let indeterminate = store.transition(
        &issuing,
        XfrmObjectInstallDurablePhase::Issuing,
        XfrmObjectInstallDurablePhase::Indeterminate,
        None,
    )?;
    store.handle_for_record(&indeterminate)
}

/// Process-loss detector seam: durably admit exact cleanup for an acquired
/// object, optionally issue the deletion, and stop before publishing
/// `Retired`.
///
/// The live production recovery path performs the same authenticated restore,
/// `Acquired -> RemovalAdmitted` transition, and exact deletion. Leaving the
/// record at `RemovalAdmitted` models a crash after the deletion was admitted
/// (including after the kernel effect but before its acknowledgement was
/// durably reflected). The returned handle authenticates the current cut
/// record for privileged restart detectors.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_object_install_at_removal_admitted<B>(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
    admit_backend_effect: bool,
) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let fingerprints = store.fingerprints_for_request(request)?;
    let acquired = store.restore(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )?;
    let admitted = store.transition(
        &store.handle_for_record(&acquired)?,
        XfrmObjectInstallDurablePhase::Acquired,
        XfrmObjectInstallDurablePhase::RemovalAdmitted,
        None,
    )?;
    if admit_backend_effect {
        // Deliberately omit the terminal publication regardless of the reply.
        // Restart recovery must safely retry an exact delete or observe
        // NotFound while the durable removal authority remains intact.
        let _ = remove(backend, &request.removal(), request.policy_if_id()).await;
    }
    store.handle_for_record(&admitted)
}

pub(crate) fn finalize_durable_object_install(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )?;
    let handle = store.handle_for_record(&record)?;
    match record.phase {
        XfrmObjectInstallDurablePhase::Acquired => store
            .transition(
                &handle,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::Committed,
                None,
            )
            .map(|record| record.phase),
        XfrmObjectInstallDurablePhase::NoMutation => store
            .transition(
                &handle,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )
            .map(|record| record.phase),
        XfrmObjectInstallDurablePhase::Committed | XfrmObjectInstallDurablePhase::Retired => {
            Ok(record.phase)
        }
        _ => Err(XfrmObjectInstallDurableError::InvalidTransition),
    }
}

pub(crate) async fn recover_durable_object_install<B>(
    store: &XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: &XfrmObjectInstallRequest,
    backend: &B,
) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let removal = request.removal();
    let fingerprints = store.fingerprints_for_request(request)?;
    let record = store.restore(
        operation_id,
        operation_generation,
        request.object(),
        fingerprints,
    )?;

    match record.phase {
        XfrmObjectInstallDurablePhase::Prepared => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::NoMutation)
        }
        XfrmObjectInstallDurablePhase::NoMutation => {
            store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::NoMutation)
        }
        XfrmObjectInstallDurablePhase::Acquired => {
            let admitted = store.transition(
                &store.handle_for_record(&record)?,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                None,
            )?;
            retire_admitted(store, admitted, &removal, request.policy_if_id(), backend).await
        }
        XfrmObjectInstallDurablePhase::RemovalAdmitted => {
            retire_admitted(store, record, &removal, request.policy_if_id(), backend).await
        }
        XfrmObjectInstallDurablePhase::Issuing | XfrmObjectInstallDurablePhase::Indeterminate => {
            reconcile_unresolved(store, record, request, &removal, backend).await
        }
        XfrmObjectInstallDurablePhase::Committed => Ok(XfrmObjectInstallRestartOutcome::Committed),
        XfrmObjectInstallDurablePhase::Retired => Ok(XfrmObjectInstallRestartOutcome::Retired),
    }
}

/// Reconcile an `Issuing` or `Indeterminate` record by combining its durable
/// pre-effect proof with a fresh exact readback of the deletion identity.
///
/// The proof was witnessed before any possible backend effect admission.
/// Because the extended writer gate excluded every other cooperating writer
/// for the whole time the record remained unresolved, the proof plus the
/// current readback is sufficient to classify the exact identity:
///
/// - absent + `Absent`: the effect provably never happened; retire as
///   no-mutation without any deletion.
/// - present + `Absent`: the identity appeared inside this operation's effect
///   window and can only be this operation's residue; admit and remove it.
/// - present + `Conflict`: the identity was witnessed before admission and no
///   install effect followed; leave the foreign state untouched and retire.
/// - absent + `Conflict`: the pre-existing conflict is gone; because no
///   install effect followed, retire as no-mutation.
///
/// A readback failure leaves the record unresolved and retryable. A durable
/// anomaly (stale epoch or missing proof) is classified for repair and the
/// record keeps gating cooperating writers.
async fn reconcile_unresolved<B>(
    store: &XfrmObjectInstallRecoveryStore,
    record: DurableObjectRecord,
    request: &XfrmObjectInstallRequest,
    removal: &XfrmObjectRemovalRequest,
    backend: &B,
) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let phase = record.phase;
    let Some(proof) = record.pre_effect_proof else {
        return Ok(XfrmObjectInstallRestartOutcome::RepairRequired);
    };
    if !store.record_writer_epoch_is_current(&record)? {
        return Ok(XfrmObjectInstallRestartOutcome::RepairRequired);
    }
    let present = match readback_object_present(backend, request).await {
        Ok(present) => present,
        Err(_) => return Ok(XfrmObjectInstallRestartOutcome::Indeterminate),
    };
    let handle = store.handle_for_record(&record)?;
    match (present, proof) {
        (false, XfrmObjectInstallPreEffectProof::Absent)
        | (false, XfrmObjectInstallPreEffectProof::Conflict) => {
            retire_through_no_mutation(store, &handle, phase)?;
            Ok(XfrmObjectInstallRestartOutcome::NoMutation)
        }
        (true, XfrmObjectInstallPreEffectProof::Absent) => {
            let admitted = store.transition(
                &handle,
                phase,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                None,
            )?;
            retire_admitted(store, admitted, removal, request.policy_if_id(), backend).await
        }
        (true, XfrmObjectInstallPreEffectProof::Conflict) => {
            retire_through_no_mutation(store, &handle, phase)?;
            Ok(XfrmObjectInstallRestartOutcome::ForeignUntouched)
        }
    }
}

fn retire_through_no_mutation(
    store: &XfrmObjectInstallRecoveryStore,
    handle: &XfrmObjectInstallRecoveryHandle,
    phase: XfrmObjectInstallDurablePhase,
) -> Result<(), XfrmObjectInstallDurableError> {
    let no_mutation = store.transition(
        handle,
        phase,
        XfrmObjectInstallDurablePhase::NoMutation,
        None,
    )?;
    store.transition(
        &store.handle_for_record(&no_mutation)?,
        XfrmObjectInstallDurablePhase::NoMutation,
        XfrmObjectInstallDurablePhase::Retired,
        None,
    )?;
    Ok(())
}

/// Exact presence readback of the deletion identity for an install request.
///
/// Returns `Ok(true)` when the identity is present, `Ok(false)` when it is
/// definitively absent, and `Err` when the readback itself cannot be trusted.
/// This is observation only; it never authorizes a mutation on its own.
pub(crate) async fn readback_object_present<B>(
    backend: &B,
    request: &XfrmObjectInstallRequest,
) -> Result<bool, XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    match request {
        XfrmObjectInstallRequest::Sa(request) => {
            let parameters = &request.parameters;
            let mut query = QuerySaRequest::new(
                parameters.id.destination,
                parameters.id.protocol,
                parameters.id.spi,
            );
            if let Some(mark) = parameters.mark {
                query = query.with_mark(mark);
            }
            match backend.query_sa(query).await {
                Ok(_) => Ok(true),
                Err(XfrmError::NotFound) => Ok(false),
                Err(error) => Err(error),
            }
        }
        XfrmObjectInstallRequest::Policy(request) => {
            let parameters = &request.parameters;
            let mut query =
                QueryPolicyRequest::new(parameters.selector.clone(), parameters.direction);
            if let Some(mark) = parameters.mark {
                query = query.with_mark(mark);
            }
            query = query.with_optional_if_id(match parameters.if_id {
                Some(if_id) if if_id != 0 => Some(if_id),
                _ => None,
            });
            match backend.query_policy(query).await {
                Ok(_) => Ok(true),
                Err(XfrmError::NotFound) => Ok(false),
                Err(error) => Err(error),
            }
        }
    }
}

async fn retire_admitted<B>(
    store: &XfrmObjectInstallRecoveryStore,
    admitted: DurableObjectRecord,
    removal: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
    backend: &B,
) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>
where
    B: XfrmBackend + ?Sized,
{
    match remove(backend, removal, policy_if_id).await {
        Ok(()) | Err(XfrmError::NotFound) => {
            store.transition(
                &store.handle_for_record(&admitted)?,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )?;
            Ok(XfrmObjectInstallRestartOutcome::OwnedResidueRetired)
        }
        Err(source) => Ok(XfrmObjectInstallRestartOutcome::RemovalPending { source }),
    }
}

async fn install<B>(backend: &B, request: &XfrmObjectInstallRequest) -> Result<(), XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    match request {
        XfrmObjectInstallRequest::Sa(request) => backend.install_sa(request.clone()).await,
        XfrmObjectInstallRequest::Policy(request) => backend.install_policy(request.clone()).await,
    }
}

async fn remove<B>(
    backend: &B,
    request: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
) -> Result<(), XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    match request {
        XfrmObjectRemovalRequest::Sa(request) => backend.remove_sa(*request).await,
        XfrmObjectRemovalRequest::Policy(request) => match policy_if_id {
            Some(if_id) => {
                backend
                    .remove_policy_exact(
                        ExactRemovePolicyRequest::new(request.clone()).with_if_id(if_id),
                    )
                    .await
            }
            None => backend.remove_policy(request.clone()).await,
        },
    }
}

/// SA-only install request used by sibling-module recovery tests that need a
/// fingerprintable request without depending on this module's private helpers.
#[cfg(test)]
pub(crate) fn tests_sa_request_for_repair() -> XfrmObjectInstallRequest {
    use crate::{InstallSaRequest, IpAddress, SaParameters, XfrmId, XfrmMode, XfrmSelector};
    let selector = XfrmSelector::new(
        IpAddress::Ipv4([10, 67, 0, 1]),
        IpAddress::Ipv4([198, 51, 100, 19]),
        50,
    );
    XfrmObjectInstallRequest::Sa(InstallSaRequest {
        parameters: SaParameters {
            selector,
            id: XfrmId {
                destination: IpAddress::Ipv4([198, 51, 100, 19]),
                spi: 0x6160_0001,
                protocol: 50,
            },
            source_address: IpAddress::Ipv4([10, 67, 0, 1]),
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
        },
    })
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
        AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
        MockOperation, MockXfrmBackend, PolicyParameters, SaParameters, XfrmAction, XfrmDirection,
        XfrmId, XfrmLookupMark, XfrmMode, XfrmSelector, XfrmTemplate,
    };

    use super::*;
    use crate::durable_object::XfrmObjectRecoveryProofKey;

    const NAMESPACE_BINDING: [u8; 40] = [0xa5; 40];
    const PROOF_KEY_BYTE: u8 = 0x91;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            for _ in 0..8 {
                let identity = XfrmObjectInstallOperationId::generate().unwrap();
                let name = identity
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let path =
                    std::env::temp_dir().join(format!("opc-xfrm-durable-install-test-{name}"));
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

    fn proof_key() -> XfrmObjectRecoveryProofKey {
        XfrmObjectRecoveryProofKey::new([PROOF_KEY_BYTE; 32]).unwrap()
    }

    fn open_store(root: &TestRoot) -> XfrmObjectInstallRecoveryStore {
        XfrmObjectInstallRecoveryStore::open_bound(root.path(), proof_key(), NAMESPACE_BINDING)
            .unwrap()
    }

    fn operation(byte: u8) -> XfrmObjectInstallOperationId {
        XfrmObjectInstallOperationId::from_bytes([byte; 16]).unwrap()
    }

    fn generation(value: u64) -> XfrmObjectInstallOperationGeneration {
        XfrmObjectInstallOperationGeneration::new(value).unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 67, 0, 1), ipv4(198, 51, 100, 19), 50)
    }

    fn sa_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: SaParameters {
                selector: selector(),
                id: XfrmId {
                    destination: ipv4(198, 51, 100, 19),
                    spi: 0x6160_0001,
                    protocol: 50,
                },
                source_address: ipv4(10, 67, 0, 1),
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
            },
        })
    }

    fn policy_request(if_id: Option<u32>) -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
            parameters: PolicyParameters {
                selector: selector(),
                direction: XfrmDirection::Out,
                action: XfrmAction::Allow,
                priority: 616,
                templates: vec![XfrmTemplate {
                    id: XfrmId {
                        destination: ipv4(198, 51, 100, 19),
                        spi: 0x6160_0001,
                        protocol: 50,
                    },
                    source_address: ipv4(10, 67, 0, 1),
                    request_id: None,
                    mode: XfrmMode::Tunnel,
                }],
                mark: None,
                if_id,
            },
        })
    }

    fn assert_no_removal(backend: &MockXfrmBackend) {
        assert!(backend.operations().iter().all(|operation| !matches!(
            operation,
            MockOperation::RemoveSa { .. } | MockOperation::RemovePolicy { .. }
        )));
    }

    async fn assert_present(backend: &MockXfrmBackend, request: &XfrmObjectInstallRequest) {
        assert!(matches!(
            install(backend, request).await,
            Err(XfrmError::AlreadyExists)
        ));
    }

    async fn run_durable_object_install(
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: &XfrmObjectInstallRequest,
        backend: &MockXfrmBackend,
    ) -> Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallDurableError> {
        // Mirror the namespace actor: prepare (which validates the removal
        // identity), then witness the exact deletion identity before admitting
        // the effect, then issue with that proof.
        let prepared =
            prepare_durable_object_install(store, operation_id, operation_generation, request)?;
        let proof = match readback_object_present(backend, request).await {
            Ok(true) => XfrmObjectInstallPreEffectProof::Conflict,
            Ok(false) => XfrmObjectInstallPreEffectProof::Absent,
            Err(source) => panic!("pre-effect readback failed in test helper: {source}"),
        };
        issue_durable_object_install(
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

    /// Drive an operation to `Issuing` with a witnessed proof but without
    /// admitting the backend effect, simulating a crash cut after the durable
    /// `Issuing` publication and before the install call.
    fn issuing_cut(
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: &XfrmObjectInstallRequest,
        proof: XfrmObjectInstallPreEffectProof,
    ) -> XfrmObjectInstallRecoveryHandle {
        let prepared =
            prepare_durable_object_install(store, operation_id, operation_generation, request)
                .unwrap();
        store
            .transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(proof),
            )
            .unwrap();
        prepared
    }

    #[tokio::test]
    async fn acquired_sa_and_policy_are_exactly_removed_after_restart() {
        for (case, request) in [(0x11, sa_request()), (0x12, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(1);
            let store = open_store(&root);

            let outcome = run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "acquired");
            assert_eq!(
                store.inspect(outcome.handle()).unwrap(),
                XfrmObjectInstallDurablePhase::Acquired
            );

            drop(store);
            backend.clear_operations();
            let reopened = open_store(&root);
            let recovered = recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "owned_residue_retired");
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "retired"
            );
            install(&backend, &request)
                .await
                .expect("recovery must remove exactly the acquired object");
        }
    }

    #[tokio::test]
    async fn preexisting_sa_and_policy_are_never_deleted_after_already_exists() {
        for (case, request) in [(0x21, sa_request()), (0x22, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            install(&backend, &request).await.unwrap();
            backend.clear_operations();
            let operation_id = operation(case);
            let operation_generation = generation(2);
            let store = open_store(&root);

            let outcome = run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "no_mutation");
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
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
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn failed_install_after_witnessed_absence_recovers_no_mutation() {
        for (case, request) in [(0x31, sa_request()), (0x32, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(3);
            let store = open_store(&root);

            // Witness absence before the effect, then make the install itself
            // fail with a non-definitive error so the durable terminal phase is
            // `Indeterminate`.
            let proof = match readback_object_present(&backend, &request).await {
                Ok(false) => XfrmObjectInstallPreEffectProof::Absent,
                other => panic!("expected absent pre-effect readback, got {other:?}"),
            };
            backend.set_failure(XfrmError::Unavailable);
            let prepared = prepare_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
            )
            .unwrap();
            let outcome = issue_durable_object_install(
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
            assert!(matches!(outcome.source(), Some(XfrmError::Unavailable)));
            drop(store);

            backend.clear_failure();
            backend.clear_operations();
            let reopened = open_store(&root);
            // The failed install never mutated the backend, so the fresh
            // readback proves absence and the record retires as no-mutation
            // without any deletion.
            assert_eq!(
                recover_durable_object_install(
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
        }
    }

    #[tokio::test]
    async fn indeterminate_after_effect_retires_exact_owned_residue_and_gates_writers() {
        for (case, request) in [(0x35, sa_request()), (0x36, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(3);
            let store = open_store(&root);

            // Model an install whose effect reached the backend but whose
            // acknowledgement was lost: durable truth advances from Issuing
            // to Indeterminate while preserving the witnessed absence proof.
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            install(&backend, &request).await.unwrap();
            let fingerprints = store.fingerprints_for_request(&request).unwrap();
            let issuing = store
                .restore(
                    operation_id,
                    operation_generation,
                    request.object(),
                    fingerprints,
                )
                .unwrap();
            let handle = store.handle_for_record(&issuing).unwrap();
            let indeterminate = store
                .transition(
                    &handle,
                    XfrmObjectInstallDurablePhase::Issuing,
                    XfrmObjectInstallDurablePhase::Indeterminate,
                    None,
                )
                .unwrap();
            assert_eq!(
                indeterminate.pre_effect_proof,
                Some(XfrmObjectInstallPreEffectProof::Absent)
            );
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmObjectInstallDurableError::InvalidTransition),
                "Indeterminate owned residue must keep the writer gate closed"
            );
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "owned_residue_retired"
            );
            install(&backend, &request)
                .await
                .expect("recovery must remove exact Indeterminate owned residue");
            assert!(reopened.advance_writer_epoch().is_ok());
        }
    }

    #[tokio::test]
    async fn unresolved_recovery_with_failing_readback_stays_indeterminate_and_retryable() {
        for (case, request) in [(0x33, sa_request()), (0x34, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(3);
            let store = open_store(&root);
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            drop(store);

            let reopened = open_store(&root);
            backend.set_failure(XfrmError::Unavailable);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
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
            assert_no_removal(&backend);
            // The record is still unresolved and keeps gating writers.
            assert_eq!(
                reopened.advance_writer_epoch(),
                Err(XfrmObjectInstallDurableError::InvalidTransition)
            );
            // Once readback is trustworthy again the same record converges.
            backend.clear_failure();
            backend.clear_operations();
            assert_eq!(
                recover_durable_object_install(
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
        }
    }

    #[tokio::test]
    async fn crash_after_prepare_never_deletes_a_preexisting_object() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = policy_request(None);
        install(&backend, &request).await.unwrap();
        let operation_id = operation(0x40);
        let operation_generation = generation(4);
        let store = open_store(&root);
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        store
            .prepare(
                operation_id,
                operation_generation,
                request.object(),
                fingerprints,
            )
            .unwrap();
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
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
        assert_present(&backend, &request).await;
    }

    #[tokio::test]
    async fn crash_in_issuing_after_a_successful_mutation_retires_owned_residue() {
        for (case, request) in [(0x41, sa_request()), (0x42, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(4);
            let store = open_store(&root);
            // Durable `Issuing` with a witnessed absence proof, then the kernel
            // object is created but the terminal publication never happens.
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            install(&backend, &request).await.unwrap();
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "owned_residue_retired"
            );
            // The owned residue was removed exactly; installing again must now
            // succeed, and a repeat recovery is idempotent.
            install(&backend, &request)
                .await
                .expect("recovery must remove exactly the owned residue");
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "retired"
            );
        }
    }

    #[tokio::test]
    async fn crash_in_issuing_with_conflict_proof_leaves_foreign_state_untouched() {
        for (case, request) in [(0x43, sa_request()), (0x44, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            // Pre-existing exact state witnessed as a conflict before the
            // effect was admitted.
            install(&backend, &request).await.unwrap();
            let operation_id = operation(case);
            let operation_generation = generation(4);
            let store = open_store(&root);
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Conflict,
            );
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "foreign_untouched"
            );
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn crash_before_effect_with_absent_proof_recovers_without_deletion() {
        for (case, request) in [(0x45, sa_request()), (0x46, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(4);
            let store = open_store(&root);
            // Crash after durable `Issuing` but before the backend call. The
            // object was never created.
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
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
            install(&backend, &request)
                .await
                .expect("no object may have been removed");
        }
    }

    #[tokio::test]
    async fn committed_old_receipt_never_deletes_a_replacement() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x51);
        let operation_generation = generation(5);
        let store = open_store(&root);
        let outcome = run_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        assert_eq!(outcome.as_str(), "acquired");
        let old_handle = outcome.handle().clone();
        assert_eq!(
            finalize_durable_object_install(&store, operation_id, operation_generation, &request,)
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        assert!(store.inspect(&old_handle).is_err());

        remove(&backend, &request.removal(), request.policy_if_id())
            .await
            .unwrap();
        install(&backend, &request).await.unwrap();
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "committed"
        );
        assert_no_removal(&backend);
        assert_present(&backend, &request).await;
    }

    #[tokio::test]
    async fn scoped_policy_recovery_removes_only_the_exact_interface_identity() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let unscoped = policy_request(None);
        let scoped = policy_request(Some(77));
        install(&backend, &unscoped).await.unwrap();
        let operation_id = operation(0x61);
        let operation_generation = generation(6);
        let store = open_store(&root);
        assert_eq!(
            run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &scoped,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "acquired"
        );
        drop(store);

        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &scoped,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
        assert_present(&backend, &unscoped).await;
        install(&backend, &scoped)
            .await
            .expect("the scoped identity must have been removed");
    }

    #[tokio::test]
    async fn narrow_lookup_marks_are_rejected_before_recording_or_backend_mutation() {
        for (case, mut request) in [(0x69, sa_request()), (0x6a, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(6);
            let narrow = XfrmLookupMark::new(0x10, 0xf0).unwrap();
            match &mut request {
                XfrmObjectInstallRequest::Sa(request) => request.parameters.mark = Some(narrow),
                XfrmObjectInstallRequest::Policy(request) => {
                    request.parameters.mark = Some(narrow);
                }
            }
            let store = open_store(&root);

            assert!(matches!(
                run_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await,
                Err(XfrmObjectInstallDurableError::NonExactRemovalIdentity)
            ));
            assert!(backend.operations().is_empty());

            let full = XfrmLookupMark::full(0x10);
            match &mut request {
                XfrmObjectInstallRequest::Sa(request) => request.parameters.mark = Some(full),
                XfrmObjectInstallRequest::Policy(request) => {
                    request.parameters.mark = Some(full);
                }
            }
            assert_eq!(
                run_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "acquired"
            );
            // Exactly one backend mutation; a pre-effect SA readback may also
            // be recorded as an observation, so count mutations only.
            let mutations = backend
                .operations()
                .iter()
                .filter(|operation| {
                    matches!(
                        operation,
                        MockOperation::InstallSa { .. } | MockOperation::InstallPolicy { .. }
                    )
                })
                .count();
            assert_eq!(mutations, 1);
        }
    }

    #[tokio::test]
    async fn wrong_correlation_and_tampered_handle_cannot_trigger_removal() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x71);
        let operation_generation = generation(7);
        let store = open_store(&root);
        let outcome = run_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        let mut tampered_bytes = outcome.handle().to_bytes();
        tampered_bytes[tampered_bytes.len() - 1] ^= 1;
        let tampered = XfrmObjectInstallRecoveryHandle::from_bytes(tampered_bytes);
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        assert!(matches!(
            store.restore_handle(&tampered, request.object(), fingerprints),
            Err(XfrmObjectInstallDurableError::AuthenticationFailed)
        ));

        backend.clear_operations();
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation_id,
                generation(8),
                &request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::NotFound)
        ));
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation(0x72),
                operation_generation,
                &request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::NotFound)
        ));
        let mut wrong_request = request.clone();
        let XfrmObjectInstallRequest::Sa(wrong_sa) = &mut wrong_request else {
            unreachable!();
        };
        wrong_sa.parameters.id.spi ^= 1;
        assert!(matches!(
            recover_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &wrong_request,
                &backend,
            )
            .await,
            Err(XfrmObjectInstallDurableError::WrongBinding)
        ));
        assert_no_removal(&backend);
        assert_present(&backend, &request).await;

        backend.clear_operations();
        assert_eq!(
            recover_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
    }

    #[tokio::test]
    async fn full_install_payload_is_bound_independently_from_deletion_identity() {
        for (case, request, wrong_request) in {
            let sa = sa_request();
            let mut wrong_sa = sa.clone();
            let XfrmObjectInstallRequest::Sa(changed) = &mut wrong_sa else {
                unreachable!();
            };
            changed.parameters.auth = Some((
                AuthAlgorithm::hmac_sha256(128),
                KeyMaterial::new(vec![0x5a; 32]),
            ));

            let policy = policy_request(Some(616));
            let mut wrong_policy = policy.clone();
            let XfrmObjectInstallRequest::Policy(changed) = &mut wrong_policy else {
                unreachable!();
            };
            changed.parameters.priority += 1;
            changed.parameters.templates[0].mode = XfrmMode::Transport;
            [(0x73, sa, wrong_sa), (0x74, policy, wrong_policy)]
        } {
            assert_eq!(request.removal(), wrong_request.removal());
            assert_eq!(request.policy_if_id(), wrong_request.policy_if_id());

            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let store = open_store(&root);
            run_durable_object_install(&store, operation(case), generation(7), &request, &backend)
                .await
                .unwrap();

            backend.clear_operations();
            assert!(matches!(
                recover_durable_object_install(
                    &store,
                    operation(case),
                    generation(7),
                    &wrong_request,
                    &backend,
                )
                .await,
                Err(XfrmObjectInstallDurableError::WrongBinding)
            ));
            assert!(backend.operations().is_empty());
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn admitted_removal_failure_is_durable_and_retryable_after_restart() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x81);
        let operation_generation = generation(8);
        let store = open_store(&root);
        assert_eq!(
            run_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "acquired"
        );
        backend.set_failure(XfrmError::Unavailable);
        let first_recovery = recover_durable_object_install(
            &store,
            operation_id,
            operation_generation,
            &request,
            &backend,
        )
        .await
        .unwrap();
        assert_eq!(first_recovery.as_str(), "removal_pending");
        assert!(matches!(
            first_recovery.source(),
            Some(XfrmError::Unavailable)
        ));
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        assert_eq!(
            store
                .restore(
                    operation_id,
                    operation_generation,
                    request.object(),
                    fingerprints,
                )
                .unwrap()
                .phase,
            XfrmObjectInstallDurablePhase::RemovalAdmitted
        );
        drop(store);

        backend.clear_failure();
        backend.clear_operations();
        let reopened = open_store(&root);
        assert_eq!(
            recover_durable_object_install(
                &reopened,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap()
            .as_str(),
            "owned_residue_retired"
        );
        install(&backend, &request)
            .await
            .expect("retry must remove the admitted residue");
    }

    #[tokio::test]
    async fn conflict_object_removed_before_recovery_recovers_no_mutation() {
        for (case, request) in [(0x91, sa_request()), (0x92, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            // A conflict is witnessed before the effect, then the foreign
            // object disappears before recovery runs.
            install(&backend, &request).await.unwrap();
            let operation_id = operation(case);
            let operation_generation = generation(9);
            let store = open_store(&root);
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Conflict,
            );
            remove(&backend, &request.removal(), request.policy_if_id())
                .await
                .unwrap();
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
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
        }
    }

    #[tokio::test]
    async fn unresolved_record_gates_a_second_operation_until_recovered() {
        let root = TestRoot::new();
        let backend = MockXfrmBackend::new();
        let request = sa_request();
        let operation_id = operation(0x93);
        let operation_generation = generation(9);
        let store = open_store(&root);
        issuing_cut(
            &store,
            operation_id,
            operation_generation,
            &request,
            XfrmObjectInstallPreEffectProof::Absent,
        );
        // A distinct operation cannot be prepared or admitted while the
        // unresolved record remains.
        assert_eq!(
            prepare_durable_object_install(
                &store,
                operation(0x94),
                generation(9),
                &policy_request(None),
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        // Recovery retires the record and reopens the gate.
        assert_eq!(
            recover_durable_object_install(
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
        assert!(store.advance_writer_epoch().is_ok());
        assert!(prepare_durable_object_install(
            &store,
            operation(0x94),
            generation(9),
            &policy_request(None),
        )
        .is_ok());
    }

    #[tokio::test]
    async fn replacement_installed_after_owned_residue_retirement_survives_idempotent_recovery() {
        for (case, request) in [(0x95, sa_request()), (0x96, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(10);
            let store = open_store(&root);
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            install(&backend, &request).await.unwrap();
            drop(store);

            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "owned_residue_retired"
            );

            // The product replaces the retired identity. A repeated recovery
            // must be idempotent and must never touch the replacement.
            install(&backend, &request).await.unwrap();
            backend.clear_operations();
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "retired"
            );
            assert_no_removal(&backend);
            assert_present(&backend, &request).await;
        }
    }

    #[tokio::test]
    async fn removal_failure_after_issuing_admission_is_durable_and_retryable_after_restart() {
        for (case, request) in [(0x97, sa_request()), (0x98, policy_request(None))] {
            let root = TestRoot::new();
            let backend = MockXfrmBackend::new();
            let operation_id = operation(case);
            let operation_generation = generation(11);
            let store = open_store(&root);
            issuing_cut(
                &store,
                operation_id,
                operation_generation,
                &request,
                XfrmObjectInstallPreEffectProof::Absent,
            );
            install(&backend, &request).await.unwrap();
            // Reconciliation admitted the owned residue through the Issuing
            // entry edge; the process then dies during the durable deletion.
            let fingerprints = store.fingerprints_for_request(&request).unwrap();
            let issuing_record = store
                .restore(
                    operation_id,
                    operation_generation,
                    request.object(),
                    fingerprints,
                )
                .unwrap();
            let issuing_handle = store.handle_for_record(&issuing_record).unwrap();
            let admitted = store
                .transition(
                    &issuing_handle,
                    XfrmObjectInstallDurablePhase::Issuing,
                    XfrmObjectInstallDurablePhase::RemovalAdmitted,
                    None,
                )
                .unwrap();
            assert_eq!(
                admitted.pre_effect_proof,
                Some(XfrmObjectInstallPreEffectProof::Absent)
            );
            backend.set_failure(XfrmError::Unavailable);
            let first = recover_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                &request,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(first.as_str(), "removal_pending");
            assert!(matches!(first.source(), Some(XfrmError::Unavailable)));
            assert_eq!(
                store
                    .restore(
                        operation_id,
                        operation_generation,
                        request.object(),
                        fingerprints,
                    )
                    .unwrap()
                    .phase,
                XfrmObjectInstallDurablePhase::RemovalAdmitted
            );
            drop(store);

            backend.clear_failure();
            backend.clear_operations();
            let reopened = open_store(&root);
            assert_eq!(
                recover_durable_object_install(
                    &reopened,
                    operation_id,
                    operation_generation,
                    &request,
                    &backend,
                )
                .await
                .unwrap()
                .as_str(),
                "owned_residue_retired"
            );
            install(&backend, &request)
                .await
                .expect("retry must remove the admitted residue");
        }
    }

    #[test]
    fn recovery_outcome_labels_and_diagnostics_are_value_free() {
        for (outcome, label) in [
            (XfrmObjectInstallRestartOutcome::NoMutation, "no_mutation"),
            (
                XfrmObjectInstallRestartOutcome::OwnedResidueRetired,
                "owned_residue_retired",
            ),
            (
                XfrmObjectInstallRestartOutcome::Indeterminate,
                "indeterminate",
            ),
            (
                XfrmObjectInstallRestartOutcome::ForeignUntouched,
                "foreign_untouched",
            ),
            (
                XfrmObjectInstallRestartOutcome::RepairRequired,
                "repair_required",
            ),
        ] {
            assert_eq!(outcome.as_str(), label);
            let debug = format!("{outcome:?}");
            assert!(debug.contains(label), "debug must carry only the label");
        }
        // Diagnostics must not leak identity material.
        let rendered = format!(
            "{:?} {:?} {:?}",
            XfrmObjectInstallRestartOutcome::ForeignUntouched,
            XfrmObjectInstallRestartOutcome::RepairRequired,
            XfrmObjectInstallPreEffectProof::Conflict,
        );
        for leaked in ["10.67", "198.51", "6160", "0x6160"] {
            assert!(!rendered.contains(leaked), "diagnostic leaked {leaked}");
        }
    }
}
