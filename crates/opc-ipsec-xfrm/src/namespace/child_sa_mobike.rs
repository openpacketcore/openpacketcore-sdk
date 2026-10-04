//! Authenticated whole-roster commands on the existing namespace writer actor.

use super::*;
use crate::child_sa_relocation::mismatch;
use crate::durable_relocation::XfrmSaRelocationPreEffectProof;
use crate::{ChildSaRelocationError, ChildSaRelocationIntent, XfrmCapability};
use opc_proto_ikev2::nwu::mobike::{MigrationAssociation, MigrationPermit};

/// Caller-established association of one live IKE responder and installed roster.
///
/// The caller owns the IKE-to-Child-SA relationship and must bind it before
/// admitting an authenticated update. Equal public SPIs or caller labels cannot
/// reconstruct this opaque association. Any later actor mutation retires its
/// installed publication; a fresh binding then requires fresh whole readback.
pub struct ChildSaMobikeAssociation {
    roster: InstalledChildSaRoster,
    ike: MigrationAssociation,
}

/// Affine authority for one durably prepared complete Child-SA relocation.
///
/// Dropping this value leaves a Prepared journal gate requiring recovery. The
/// permit, actor, store, exact request and private live admission seal cannot be
/// replaced or restored from caller-supplied generation labels.
#[must_use = "dropping this authority leaves a durable relocation to reconcile"]
pub struct ChildSaRelocationAuthority {
    operation: Operation,
    association: ChildSaMobikeAssociation,
    permit: MigrationPermit,
    prepared: XfrmSaRelocationRecoveryHandle,
    actor_binding: NamespaceActorBinding,
    seal: Arc<()>,
}

/// One completed, freshly read-back publication for the entire moved roster.
pub struct ChildSaRelocationReceipt {
    roster: InstalledChildSaRoster,
    handle: XfrmSaRelocationRecoveryHandle,
}

impl ChildSaRelocationReceipt {
    /// Borrow the current installed publication; every later actor write retires it.
    pub const fn roster(&self) -> &InstalledChildSaRoster {
        &self.roster
    }
    /// Opaque durable correlation, which grants no live migration authority.
    pub const fn recovery_handle(&self) -> &XfrmSaRelocationRecoveryHandle {
        &self.handle
    }
}

/// Reconciliation outcome without a live IKE or installed-roster publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildSaRelocationRecovery {
    /// The original Prepared record was retired without admitting effects.
    NoMutation,
    /// Every member of the previously admitted target is freshly proven complete.
    Completed,
}

macro_rules! redacted {
    ($($name:ident),+ $(,)?) => {$(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($name), "(<redacted>)"))
        }
    })+};
}
redacted!(
    ChildSaMobikeAssociation,
    ChildSaRelocationAuthority,
    ChildSaRelocationReceipt
);

pub(super) struct Operation {
    store: XfrmSaRelocationRecoveryStore,
    id: XfrmSaRelocationOperationId,
    generation: XfrmSaRelocationOperationGeneration,
    intent: ChildSaRelocationIntent,
}

pub(super) struct Preparation {
    operation: Operation,
    association: ChildSaMobikeAssociation,
    permit: MigrationPermit,
}

pub(super) enum Command {
    Bind(
        InstalledChildSaRoster,
        MigrationAssociation,
        oneshot::Sender<Result<ChildSaMobikeAssociation, ChildSaRelocationError>>,
    ),
    Prepare(
        Box<Preparation>,
        oneshot::Sender<Result<ChildSaRelocationAuthority, ChildSaRelocationError>>,
    ),
    Run(
        Box<ChildSaRelocationAuthority>,
        Option<usize>,
        oneshot::Sender<Result<ChildSaRelocationReceipt, ChildSaRelocationError>>,
    ),
    Recover(
        Box<Operation>,
        oneshot::Sender<Result<ChildSaRelocationRecovery, ChildSaRelocationError>>,
    ),
}

impl NamespaceBoundLinuxXfrmBackend {
    /// Bind the caller-owned established IKE association after whole-roster readback.
    /// This records the caller's association; it does not establish IKE_AUTH trust.
    pub async fn bind_child_sa_mobike(
        &self,
        roster: &InstalledChildSaRoster,
        association: MigrationAssociation,
    ) -> Result<ChildSaMobikeAssociation, ChildSaRelocationError> {
        self.dispatch_child_sa_mobike(|reply| Command::Bind(roster.clone(), association, reply))
            .await
    }

    /// Prepare one complete authenticated move under the bound relocation store.
    ///
    /// This bounded profile supports at most eight tunnel pairs, including rekey
    /// overlap, with one shared old outer path and exact per-child outbound marks.
    /// Fixed DSCP and unchanged SA targets return precise unsupported outcomes.
    /// The single-SA kernel capability must be explicitly Available. All keys,
    /// policies, both directions, target absence and live authentication are
    /// proven before the one complete Prepared journal record is published.
    pub async fn prepare_child_sa_relocation(
        &self,
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        generation: XfrmSaRelocationOperationGeneration,
        association: ChildSaMobikeAssociation,
        intent: ChildSaRelocationIntent,
        permit: MigrationPermit,
    ) -> Result<ChildSaRelocationAuthority, ChildSaRelocationError> {
        let operation = Operation {
            store: store.clone(),
            id: operation_id,
            generation,
            intent,
        };
        self.dispatch_child_sa_mobike(|reply| {
            Command::Prepare(
                Box::new(Preparation {
                    operation,
                    association,
                    permit,
                }),
                reply,
            )
        })
        .await
    }

    /// Consume one prepared move, preserving counters through exact SA migration.
    ///
    /// The actor first replaces every exact outbound allow policy with Block,
    /// moves all SAs, updates inbound policies, then restores outbound policies.
    /// Inner selectors and key material are never changed or reinstalled. Every
    /// step is followed by whole-roster readback. The kernel steps are individual;
    /// only the final SDK publication is atomic. An error before durable terminal
    /// completion leaves the complete writer gate closed for reconciliation.
    /// A lost reply after Relocated releases that gate but transfers no receipt.
    ///
    /// Once admitted, the actor drains even if the caller drops its future.
    /// A lost reply cannot publish a usable receipt. A later accepted IKE event
    /// can stop a live move and prevents final publication; callers serialize
    /// IKE events, application sends and all namespace writers with publication.
    pub async fn run_child_sa_relocation(
        &self,
        authority: ChildSaRelocationAuthority,
    ) -> Result<ChildSaRelocationReceipt, ChildSaRelocationError> {
        self.dispatch_child_sa_mobike(|reply| Command::Run(Box::new(authority), None, reply))
            .await
    }

    /// Detector-only interruption after an exact number of acknowledged mutations.
    ///
    /// This consumes the same authority and uses the production execution path,
    /// including durable Issuing and a complete readback at the cut. It returns
    /// `StateIndeterminate` and leaves the whole writer gate closed, even when
    /// the final kernel effect completed. It never publishes an installed roster.
    /// Use only in an isolated detector namespace, then reconcile the original
    /// complete intent. A cut outside this request's bounded program is rejected
    /// before Issuing; zero cuts immediately after its durable admission.
    pub async fn detector_cut_child_sa_relocation(
        &self,
        authority: ChildSaRelocationAuthority,
        completed_mutations: usize,
    ) -> Result<(), ChildSaRelocationError> {
        self.dispatch_child_sa_mobike(|reply| {
            Command::Run(Box::new(authority), Some(completed_mutations), reply)
        })
        .await
        .map(|_| ())
    }

    /// Reconcile exactly the previously admitted target after interruption.
    ///
    /// Call before any later writer. Authentication binds every original member,
    /// key proof, class/default, incarnation and target to one durable record.
    /// Prepared recovery admits no effects. Issuing recovery resumes only a
    /// complete observed state reachable by a prefix of the original program;
    /// foreign, missing, ambiguous or unreadable state stays gated for repair.
    /// Recovery never deletes/reinstalls an SA or publishes live IKE authority.
    /// Reestablish IKE ownership and freshly publish before resuming traffic.
    pub async fn recover_child_sa_relocation(
        &self,
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        generation: XfrmSaRelocationOperationGeneration,
        intent: ChildSaRelocationIntent,
    ) -> Result<ChildSaRelocationRecovery, ChildSaRelocationError> {
        let operation = Operation {
            store: store.clone(),
            id: operation_id,
            generation,
            intent,
        };
        self.dispatch_child_sa_mobike(|reply| Command::Recover(Box::new(operation), reply))
            .await
    }

    async fn dispatch_child_sa_mobike<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, ChildSaRelocationError>>) -> Command,
    ) -> Result<T, ChildSaRelocationError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmError::Unavailable)?;
        let (sender, receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ChildSaMobike(make(sender)));
        receiver.await.map_err(|_| XfrmError::StateIndeterminate {
            operation: "child_sa_roster_relocation_reply",
        })?
    }
}

fn authenticate(
    intent: &ChildSaRelocationIntent,
    permit: &MigrationPermit,
    association: &ChildSaMobikeAssociation,
) -> Result<(), ChildSaRelocationError> {
    permit
        .validate(&association.ike)
        .map_err(|_| ChildSaRelocationError::Authentication)?;
    intent.matches_permit(permit)
}

async fn capability(backend: &LinuxXfrmBackend) -> Result<(), ChildSaRelocationError> {
    if backend.sa_relocation_capability().await? != XfrmCapability::Available {
        return Err(XfrmError::UnsupportedFeature {
            feature: "child_sa_roster_relocation",
        }
        .into());
    }
    Ok(())
}

async fn prepare(
    backend: &LinuxXfrmBackend,
    state: &mut NamespaceActorState,
    preparation: Preparation,
) -> Result<ChildSaRelocationAuthority, ChildSaRelocationError> {
    let Preparation {
        operation,
        association,
        permit,
    } = preparation;
    state.require_sa_recovery_store(&operation.store)?;
    state.require_install_gate_open_for_relocation()?;
    state.require_child_sa_publication_ready()?;
    authenticate(&operation.intent, &permit, &association)?;
    let program = operation.intent.program()?;
    operation
        .intent
        .current
        .matches_publication(&association.roster)?;
    state
        .child_sa_roster
        .select(
            &state.actor_binding,
            backend,
            &association.roster,
            ChildSaOutboundSelection::Default,
        )
        .await?;
    capability(backend).await?;
    let prefix = program.prefix(backend).await;
    if !matches!(prefix, Ok(0)) {
        state.invalidate_live_authorities();
        return Err(prefix.err().unwrap_or_else(mismatch).into());
    }
    authenticate(&operation.intent, &permit, &association)?;
    let fingerprints = operation
        .store
        .fingerprints_for_child_roster(&operation.intent, &program.updated)?;
    let prepared = operation
        .store
        .prepare(operation.id, operation.generation, fingerprints)?;
    state.invalidate_live_authorities();
    let authority = ChildSaRelocationAuthority {
        operation,
        association,
        permit,
        prepared,
        actor_binding: state.actor_binding.clone(),
        seal: Arc::new(()),
    };
    state.relocation_admissions.insert(
        (authority.operation.id, authority.operation.generation),
        Arc::downgrade(&authority.seal),
    );
    Ok(authority)
}

async fn run(
    backend: &LinuxXfrmBackend,
    state: &mut NamespaceActorState,
    authority: ChildSaRelocationAuthority,
    detector_cut: Option<usize>,
    cancelled: impl Fn() -> bool,
) -> Result<ChildSaRelocationReceipt, ChildSaRelocationError> {
    let operation = &authority.operation;
    state.require_sa_recovery_store(&operation.store)?;
    if authority.actor_binding != state.actor_binding {
        return Err(XfrmSaRelocationDurableError::WrongBinding.into());
    }
    let key = (operation.id, operation.generation);
    if !state
        .relocation_admissions
        .get(&key)
        .and_then(Weak::upgrade)
        .is_some_and(|seal| Arc::ptr_eq(&seal, &authority.seal))
    {
        return Err(XfrmSaRelocationDurableError::Stale.into());
    }
    state.require_install_gate_open_for_relocation()?;
    let guard = || authenticate(&operation.intent, &authority.permit, &authority.association);
    guard()?;
    let program = operation.intent.program()?;
    if detector_cut.is_some_and(|cut| cut > program.steps.len()) {
        return Err(
            XfrmError::invalid_config("child_sa_relocation.cut", "cut exceeds program").into(),
        );
    }
    let fingerprints = operation
        .store
        .fingerprints_for_child_roster(&operation.intent, &program.updated)?;
    let record = operation
        .store
        .restore_handle(&authority.prepared, fingerprints)?;
    if record.operation_id != operation.id
        || record.operation_generation != operation.generation
        || record.phase != XfrmSaRelocationDurablePhase::Prepared
        || !operation.store.record_writer_epoch_is_current(&record)?
    {
        return Err(XfrmSaRelocationDurableError::Stale.into());
    }
    capability(backend).await?;
    if program.prefix(backend).await? != 0 {
        return Err(mismatch().into());
    }
    guard()?;
    // Reuse the existing cross-family relocation fence before any group effect.
    state.admit_durable_sa_relocation_recovery(XfrmSaRelocationDurablePhase::Issuing)?;
    state.relocation_admissions.clear();
    let issuing = operation.store.transition(
        &authority.prepared,
        XfrmSaRelocationDurablePhase::Prepared,
        XfrmSaRelocationDurablePhase::Issuing,
        Some(XfrmSaRelocationPreEffectProof::RosterWitnessed),
    )?;
    program.finish_until(backend, guard, detector_cut).await?;
    guard()?;
    let terminal = operation.store.transition(
        &operation.store.handle_for_record(&issuing)?,
        XfrmSaRelocationDurablePhase::Issuing,
        XfrmSaRelocationDurablePhase::Relocated,
        None,
    )?;
    if cancelled() {
        return Err(XfrmError::StateIndeterminate {
            operation: "child_sa_roster_relocation_reply",
        }
        .into());
    }
    let update = state.child_sa_roster.begin(&state.actor_binding)?;
    let roster = state
        .child_sa_roster
        .publish(&state.actor_binding, backend, update, program.updated)
        .await?;
    if let Err(error) = guard() {
        state.invalidate_live_authorities();
        return Err(error);
    }
    if cancelled() {
        state.invalidate_live_authorities();
        return Err(XfrmError::StateIndeterminate {
            operation: "child_sa_roster_relocation_reply",
        }
        .into());
    }
    Ok(ChildSaRelocationReceipt {
        roster,
        handle: operation.store.handle_for_record(&terminal)?,
    })
}

async fn recover(
    backend: &LinuxXfrmBackend,
    state: &mut NamespaceActorState,
    operation: Operation,
) -> Result<ChildSaRelocationRecovery, ChildSaRelocationError> {
    let program = operation.intent.program()?;
    state.require_sa_recovery_store(&operation.store)?;
    let fingerprints = operation
        .store
        .fingerprints_for_child_roster(&operation.intent, &program.updated)?;
    let record = operation
        .store
        .restore(operation.id, operation.generation, fingerprints)?;
    state.reconcile_sa_relocation_admission(operation.id, operation.generation)?;
    state.admit_durable_sa_relocation_recovery(record.phase)?;
    let handle = operation.store.handle_for_record(&record)?;
    match record.phase {
        XfrmSaRelocationDurablePhase::Prepared => {
            operation.store.transition(
                &handle,
                record.phase,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )?;
            Ok(ChildSaRelocationRecovery::NoMutation)
        }
        XfrmSaRelocationDurablePhase::Retired if record.pre_effect_proof.is_none() => {
            Ok(ChildSaRelocationRecovery::NoMutation)
        }
        XfrmSaRelocationDurablePhase::Issuing | XfrmSaRelocationDurablePhase::Relocated => {
            if record.pre_effect_proof != Some(XfrmSaRelocationPreEffectProof::RosterWitnessed)
                || !operation.store.record_writer_epoch_is_current(&record)?
            {
                return Err(XfrmSaRelocationDurableError::Stale.into());
            }
            if record.phase == XfrmSaRelocationDurablePhase::Issuing {
                capability(backend).await?;
                program.finish(backend, || Ok(())).await?;
                operation.store.transition(
                    &handle,
                    record.phase,
                    XfrmSaRelocationDurablePhase::Relocated,
                    None,
                )?;
            } else if program.prefix(backend).await? != program.steps.len() {
                return Err(mismatch().into());
            }
            Ok(ChildSaRelocationRecovery::Completed)
        }
        _ => Err(XfrmSaRelocationDurableError::InvalidTransition.into()),
    }
}

impl Command {
    pub(super) async fn execute(self, backend: &LinuxXfrmBackend, state: &mut NamespaceActorState) {
        match self {
            Self::Bind(roster, ike, reply) => {
                let result = async {
                    state.require_child_sa_publication_ready()?;
                    state
                        .child_sa_roster
                        .select(
                            &state.actor_binding,
                            backend,
                            &roster,
                            ChildSaOutboundSelection::Default,
                        )
                        .await?;
                    Ok(ChildSaMobikeAssociation { roster, ike })
                }
                .await;
                let _ = reply.send(result);
            }
            Self::Prepare(preparation, reply) => {
                let _ = reply.send(prepare(backend, state, *preparation).await);
            }
            Self::Run(authority, detector_cut, reply) => {
                let result = run(backend, state, *authority, detector_cut, || {
                    reply.is_closed()
                })
                .await;
                if reply.send(result).is_err() {
                    state.invalidate_live_authorities();
                }
            }
            Self::Recover(operation, reply) => {
                let _ = reply.send(recover(backend, state, *operation).await);
            }
        }
    }

    pub(super) fn send_error(self, error: XfrmError) {
        match self {
            Self::Bind(_, _, reply) => {
                let _ = reply.send(Err(error.into()));
            }
            Self::Prepare(_, reply) => {
                let _ = reply.send(Err(error.into()));
            }
            Self::Run(_, _, reply) => {
                let _ = reply.send(Err(error.into()));
            }
            Self::Recover(_, reply) => {
                let _ = reply.send(Err(error.into()));
            }
        }
    }
}
