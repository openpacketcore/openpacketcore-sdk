//! The actual untimed store boundary. Public observations never mint effects.

use crate::{scope::LocalEffectOwner, LocalKernelLifecycle};
use opc_session_store::scope_authority::{
    CommittedScopeAuthority, ScopeAuthorityError, ScopeAuthorityStamp, ScopeAuthorityStore,
    ScopeAuthorityView, ScopeExecution,
};
use opc_session_store::scope_batch::{
    ScopeBatchError, ScopeBatchOutcome, ScopeBatchRequest, ScopeBatchStore, ScopeChildKey,
    ScopeChildMutation, ScopeChildReadError, ScopeChildRecord, ScopeChildRevision,
};
use opc_session_store::scope_scheduler::ScopeWorkClass;
use std::marker::PhantomData;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, Ordering},
    Arc,
};

/// Value-free failure of untimed local effect admission or publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LocalEffectError {
    /// The local process fence is irreversibly closed.
    #[error("local_effect_closed")]
    Closed,
    /// The full-round authority or exact child read no longer matches.
    #[error("local_effect_stale")]
    Stale,
    /// Scope, request, child or operation identity was changed.
    #[error("local_effect_wrong_request")]
    WrongRequest,
    /// The store proved no effect; refresh/replan before retrying. A cancelled
    /// attempt needs a successor, while an inactive profile retries exactly.
    #[error("local_effect_retryable_no_effect")]
    RetryableNoEffect,
    /// The actual store has not proved the exact activation outcome.
    #[error("local_effect_outcome_unknown")]
    OutcomeUnknown,
    /// Store or local native identity inspection is currently unavailable.
    #[error("local_effect_unavailable")]
    Unavailable,
    /// The authenticated scope transport uses another revision. This never
    /// establishes an activation outcome or requires a process restart.
    #[error("local_effect_transport_revision_mismatch")]
    TransportRevisionMismatch,
}
struct Inner {
    lifecycle: LocalKernelLifecycle,
    _owner: LocalEffectOwner,
    execution: ScopeExecution,
    committed: CommittedScopeAuthority,
    backend: Backend,
    closed: AtomicBool,
}
enum Backend {
    Local {
        authority: ScopeAuthorityStore,
        batches: ScopeBatchStore,
    },
    #[cfg(feature = "native-scope")]
    Native {
        client: opc_session_net::scope::ScopeClient,
        attempt: std::time::Duration,
    },
}
/// Sealed type state for the local store adapter. Construct it through
/// [`ScopeKernelAuthority::new`]; callers cannot supply another backend.
pub struct LocalScopeAuthority {
    _sealed: (),
}
/// Sealed type state for authenticated native readback. Mutation submission
/// remains with the shared batch coordinator; this adapter has no raw commit.
#[cfg(feature = "native-scope")]
pub struct NativeScopeAuthority {
    _sealed: (),
}
/// A concrete local adapter to the SDK's durable scope authority and batches.
///
/// Construction consumes the real non-deserializable committed capability and
/// binds one local boot to the held writer domain. Clone this adapter for every
/// backend in that domain. The host supplies its independently verified local
/// execution; this adapter does not authenticate a boot or close peer traffic.
pub struct ScopeKernelAuthority<B = LocalScopeAuthority> {
    inner: Arc<Inner>,
    backend: PhantomData<fn() -> B>,
}
impl<B> Clone for ScopeKernelAuthority<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            backend: PhantomData,
        }
    }
}
impl<B> std::fmt::Debug for ScopeKernelAuthority<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeKernelAuthority")
    }
}
impl ScopeKernelAuthority {
    /// Bind the admitted boot and verify its current untimed authority through
    /// a full-round store read. An observed stamp alone cannot construct this.
    pub async fn new(
        lifecycle: LocalKernelLifecycle,
        execution: ScopeExecution,
        committed: CommittedScopeAuthority,
        authority: ScopeAuthorityStore,
        batches: ScopeBatchStore,
    ) -> Result<Self, LocalEffectError> {
        committed
            .check_execution(&execution)
            .map_err(|_| LocalEffectError::Stale)?;
        if lifecycle.effects_closed() {
            return Err(LocalEffectError::Closed);
        }
        let owner = lifecycle
            .register_effect_owner()
            .map_err(|_| LocalEffectError::WrongRequest)?;
        let value = Self {
            inner: Arc::new(Inner {
                lifecycle,
                _owner: owner,
                execution,
                committed,
                backend: Backend::Local { authority, batches },
                closed: AtomicBool::new(false),
            }),
            backend: PhantomData,
        };
        value.current().await?;
        Ok(value)
    }
    /// Commit or recover the exact consumer activation batch and verify this
    /// child's resulting birth/revision and sealed body before yielding an
    /// effect token. The consumer chooses an activation-phase sealed payload;
    /// the SDK cannot interpret its encrypted application state.
    ///
    /// Unknown outcomes yield no token and no kernel effect. Retain/retry the
    /// identical request. This uses the actual batch service, never a supplied
    /// outcome, boolean or independently encoded digest.
    pub async fn commit_activation(
        &self,
        request: ScopeBatchRequest,
        child: ScopeChildKey,
    ) -> Result<CommittedScopeEffect, LocalEffectError> {
        let epoch = self
            .inner
            .lifecycle
            .current_effect_epoch()
            .map_err(|_| LocalEffectError::Stale)?;
        let (key, outcome, index) = commit_readback(self, request, child).await?;
        self.inner
            .effect(epoch, key, outcome, index, ScopeWorkClass::Normal)
    }
}

#[cfg(feature = "native-scope")]
impl ScopeKernelAuthority<NativeScopeAuthority> {
    /// Bind a stateless worker to its actual protected native client and genuine
    /// committed capability. Construction verifies Current once; readback and
    /// later rechecks use one current-child cut and the activation's trusted class.
    /// `class` validates the caller's data-work context; the existing Current
    /// method uses its reserved control path and cannot establish an effect class.
    pub async fn from_scope_client(
        lifecycle: LocalKernelLifecycle,
        execution: ScopeExecution,
        committed: CommittedScopeAuthority,
        client: opc_session_net::scope::ScopeClient,
        class: ScopeWorkClass,
        attempt: std::time::Duration,
    ) -> Result<Self, LocalEffectError> {
        committed
            .check_execution(&execution)
            .map_err(|_| LocalEffectError::Stale)?;
        if client.execution() != &execution
            || attempt.is_zero()
            || !matches!(
                class,
                ScopeWorkClass::Normal
                    | ScopeWorkClass::Emergency
                    | ScopeWorkClass::EmergencyClassification
                    | ScopeWorkClass::Maintenance
            )
        {
            return Err(LocalEffectError::WrongRequest);
        }
        if lifecycle.effects_closed() {
            return Err(LocalEffectError::Closed);
        }
        let owner = lifecycle
            .register_effect_owner()
            .map_err(|_| LocalEffectError::WrongRequest)?;
        let value = Self {
            inner: Arc::new(Inner {
                lifecycle,
                _owner: owner,
                execution,
                committed,
                backend: Backend::Native { client, attempt },
                closed: AtomicBool::new(false),
            }),
            backend: PhantomData,
        };
        value.current().await?;
        Ok(value)
    }

    /// Read back a genuinely supervised native Applied completion before ack.
    /// The full original request and every child field must match. The receipt
    /// stays pinned throughout this one-cut observation and local epoch check.
    /// Cancellation drops the pin without acknowledging or resubmitting work.
    ///
    /// Native authorities cannot submit an activation directly:
    /// ```compile_fail
    /// use opc_local_kernel_lifecycle::{NativeScopeAuthority, ScopeKernelAuthority};
    /// use opc_session_store::scope_batch::{ScopeBatchRequest, ScopeChildKey};
    /// async fn raw_commit(a: &ScopeKernelAuthority<NativeScopeAuthority>, r: ScopeBatchRequest, k: ScopeChildKey) {
    ///     a.commit_activation(r, k).await;
    /// }
    /// ```
    pub async fn readback_activation(
        &self,
        request: ScopeBatchRequest,
        child: ScopeChildKey,
        completion: &opc_session_store::scope_batch::ScopeBatchCompletion,
    ) -> Result<CommittedScopeEffect, LocalEffectError> {
        let epoch = self
            .inner
            .lifecycle
            .current_effect_epoch()
            .map_err(|_| LocalEffectError::Stale)?;
        let Backend::Native { client, .. } = &self.inner.backend else {
            return Err(LocalEffectError::WrongRequest);
        };
        let verified = client
            .verify_batch_completion(&self.inner.committed, &request, completion)
            .map_err(batch_error)?;
        let class = verified.class();
        let (key, outcome, index) = readback_applied(
            &EffectRead {
                inner: &self.inner,
                class,
            },
            self.inner.committed.stamp(),
            request,
            child,
            verified.outcome().clone(),
        )
        .await?;
        let effect = self.inner.effect(epoch, key, outcome, index, class)?;
        drop(verified);
        Ok(effect)
    }
}

impl<B> ScopeKernelAuthority<B> {
    async fn current(&self) -> Result<(), LocalEffectError> {
        self.inner.current().await
    }
    /// Stop new local effects and drain admitted kernel work. This does not
    /// retire forwarding or prove peer-control closure; the consumer must also
    /// close its peer paths before submitting durable execution closure.
    pub async fn close_execution(&self) {
        self.inner.lifecycle.close_effects();
        self.inner.closed.store(true, Ordering::Release);
        let _drained = self.inner.lifecycle.drain_operations().await;
    }
    /// Authorize normal local shutdown: stop new effects, drain admitted work,
    /// establish containment, and reset every declared participant in order.
    /// The consumer invokes this only after its disruption policy permits it.
    /// It does not certify peer-control closure for a durable authority Close.
    pub async fn shutdown_local(
        &self,
        participants: crate::LocalResetParticipants,
    ) -> Result<crate::LocalScopeResetReceipt, crate::LocalLifecycleError> {
        use crate::LocalLifecycleError;
        self.inner.lifecycle.local_scope().verify()?;
        self.inner.lifecycle.close_effects();
        self.inner.closed.store(true, Ordering::Release);
        let authority = self.inner.clone();
        let (reply, observed) = tokio::sync::oneshot::channel();
        // Transfer ownership before the first await. In particular, dropping
        // the caller while a prior effect still holds a read guard cannot
        // cancel the subsequent contained reset. Keep the authority owner too.
        std::thread::Builder::new()
            .name("opc-local-shutdown".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = reply.send(Err(LocalLifecycleError::Indeterminate));
                        return;
                    }
                };
                let result = runtime.block_on(authority.lifecycle.reset(participants));
                let _ = reply.send(result);
            })
            .map_err(|_| LocalLifecycleError::Indeterminate)?;
        observed
            .await
            .map_err(|_| LocalLifecycleError::Indeterminate)?
    }
}

impl Inner {
    async fn current(&self) -> Result<(), LocalEffectError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(LocalEffectError::Closed);
        }
        self.lifecycle
            .local_scope()
            .verify()
            .map_err(|_| LocalEffectError::Unavailable)?;
        let view = match &self.backend {
            Backend::Local { authority, .. } => authority
                .current(self.execution.identity())
                .await
                .map_err(authority_error)?,
            #[cfg(feature = "native-scope")]
            Backend::Native { client, attempt } => {
                tokio::time::timeout(*attempt, client.current(*attempt))
                    .await
                    .map_err(|_| LocalEffectError::Unavailable)?
                    .map_err(rpc_error)?
            }
        };
        verify_current(self.committed.stamp(), &view)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(LocalEffectError::Closed);
        }
        Ok(())
    }
    fn effect(
        self: &Arc<Self>,
        epoch: crate::LocalScopeEpoch,
        key: EffectKey,
        outcome: ScopeBatchOutcome,
        index: usize,
        class: ScopeWorkClass,
    ) -> Result<CommittedScopeEffect, LocalEffectError> {
        let consumed = self
            .lifecycle
            .effect_consumption()
            .lock()
            .map_err(|_| LocalEffectError::Unavailable)?
            .child(
                outcome.lane(),
                outcome.sequence(),
                outcome.revision(),
                outcome.rows().len(),
                index,
            )?;
        let effect = CommittedScopeEffect {
            authority: self.clone(),
            epoch,
            key,
            _outcome: outcome,
            consumed,
            class,
        };
        effect.recheck_local_execution()?;
        Ok(effect)
    }
}

/// Complete exact operation identity retained without another hash codec.
///
/// The immutable request contains the store's canonical digest inputs. Keeping
/// it whole also detects a reused request ID with changed contents; a caller's
/// request ID alone is never the comparison. Backend receipts additionally
/// bind their exact object request and local epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct EffectKey {
    request: Arc<ScopeBatchRequest>,
    child: ScopeChildKey,
    revision: ScopeChildRevision,
    batch_revision: u64,
}
impl std::fmt::Debug for EffectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EffectKey(<redacted>)")
    }
}
impl EffectKey {
    /// Exact authority, request ID and complete immutable activation command.
    pub fn request(&self) -> &ScopeBatchRequest {
        &self.request
    }
    /// Child whose committed activation this effect consumes.
    pub fn child(&self) -> ScopeChildKey {
        self.child
    }
    /// Exact committed child birth and generation.
    pub fn revision(&self) -> ScopeChildRevision {
        self.revision
    }
    /// Whole-scope batch revision that committed this exact child activation.
    pub const fn batch_revision(&self) -> u64 {
        self.batch_revision
    }
    /// Same request identity, even if changed bytes make the full key unequal.
    pub fn same_request_id(&self, other: &Self) -> bool {
        self.request.scope() == other.request.scope()
            && self.request.request_id() == other.request.request_id()
    }
}
/// Opaque actual committed activation plus exact current-child verification.
/// There is no constructor from serialized claims or a successful observation.
#[derive(Clone)]
pub struct CommittedScopeEffect {
    authority: Arc<Inner>,
    epoch: crate::LocalScopeEpoch,
    key: EffectKey,
    _outcome: ScopeBatchOutcome,
    consumed: Arc<AtomicU8>,
    class: ScopeWorkClass,
}
impl std::fmt::Debug for CommittedScopeEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommittedScopeEffect")
    }
}
impl CommittedScopeEffect {
    /// Consume this activation's one local use for a backend role. Actors
    /// first resolve an exact live retry; only a newly admitted operation
    /// consumes a use. Clones and recovered tokens share the same bits.
    ///
    /// A consumed use cannot be reinstalled after removal or failed partial
    /// installation. Commit a new activation before creating another effect.
    /// Permanent group-identity retirement remains the consumer's durable
    /// registry contract; this state retains no completed request payload.
    pub fn consume(&self, target: LocalEffectUse) -> Result<(), LocalEffectError> {
        self.recheck_local_execution()?;
        consume(&self.consumed, target)
    }
    /// Check the process fence and local epoch without a remote read. This is
    /// useful for cancellation and the final synchronous publication decision;
    /// it never replaces the full-round check before a new effect.
    pub fn recheck_local_execution(&self) -> Result<(), LocalEffectError> {
        if self.authority.closed.load(Ordering::Acquire) {
            return Err(LocalEffectError::Closed);
        }
        self.epoch.recheck().map_err(|_| LocalEffectError::Stale)
    }
    /// Require the same held reset epoch as the backend operation. A valid
    /// durable stamp cannot transplant an earlier local effect across reset.
    pub fn matches_operation(&self, operation: &crate::LocalOperation) -> bool {
        self.epoch.is_same(operation.epoch()) && self.matches_local_scope(operation.local_scope())
    }
    /// Exact committed operation facts, without granting another capability.
    pub fn key(&self) -> &EffectKey {
        &self.key
    }
    /// Verify the capability names the held local scope of the backend.
    pub fn matches_local_scope(&self, scope: &opc_linux_gtpu_sys::tc::LocalKernelScope) -> bool {
        self.authority
            .lifecycle
            .local_scope()
            .is_same_instance(scope)
    }
    /// Fresh current-execution and exact child readback before an effect or
    /// publication. Loss of the store cannot expire already published effects.
    pub async fn recheck(&self) -> Result<(), LocalEffectError> {
        self.recheck_local_execution()?;
        recheck_record(
            &EffectRead {
                inner: &self.authority,
                class: self.class,
            },
            &self.key,
        )
        .await?;
        self.recheck_local_execution()
    }
}

// Private store boundary: tests can supply untrusted observations to the same
// checks used by production, without constructing either opaque capability or
// exposing an alternative authority provider to callers.
#[async_trait::async_trait]
trait CurrentChildStore: Sync {
    async fn read_current(
        &self,
        child: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, LocalEffectError>;
}
#[async_trait::async_trait]
trait ActivationStore: CurrentChildStore {
    fn stamp(&self) -> &ScopeAuthorityStamp;
    async fn current(&self) -> Result<(), LocalEffectError>;
    async fn execute(
        &self,
        request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchOutcome, LocalEffectError>;
}
#[async_trait::async_trait]
impl ActivationStore for ScopeKernelAuthority {
    fn stamp(&self) -> &ScopeAuthorityStamp {
        self.inner.committed.stamp()
    }
    async fn current(&self) -> Result<(), LocalEffectError> {
        ScopeKernelAuthority::current(self).await
    }
    async fn execute(
        &self,
        request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchOutcome, LocalEffectError> {
        match &self.inner.backend {
            Backend::Local { batches, .. } => batches
                .execute(self.inner.execution.identity(), request)
                .await
                .map_err(batch_error),
            #[cfg(feature = "native-scope")]
            Backend::Native { .. } => Err(LocalEffectError::WrongRequest),
        }
    }
}
#[async_trait::async_trait]
impl CurrentChildStore for ScopeKernelAuthority {
    async fn read_current(
        &self,
        child: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, LocalEffectError> {
        EffectRead {
            inner: &self.inner,
            class: ScopeWorkClass::Normal,
        }
        .read_current(child)
        .await
    }
}
struct EffectRead<'a> {
    inner: &'a Inner,
    class: ScopeWorkClass,
}
#[async_trait::async_trait]
impl CurrentChildStore for EffectRead<'_> {
    async fn read_current(
        &self,
        child: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, LocalEffectError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(LocalEffectError::Closed);
        }
        self.inner
            .lifecycle
            .local_scope()
            .verify()
            .map_err(|_| LocalEffectError::Unavailable)?;
        match &self.inner.backend {
            Backend::Local { batches, .. } => {
                let mut rows = batches
                    .read_current(
                        self.inner.execution.identity(),
                        self.inner.committed.stamp(),
                        &[child],
                    )
                    .await
                    .map_err(child_read_error)?;
                if rows.len() != 1 {
                    return Err(LocalEffectError::OutcomeUnknown);
                }
                rows.pop().ok_or(LocalEffectError::OutcomeUnknown)
            }
            #[cfg(feature = "native-scope")]
            Backend::Native { client, attempt } => client
                .read_child(
                    &self.inner.committed,
                    child,
                    self.class,
                    tokio::time::Instant::now() + *attempt,
                )
                .await
                .map_err(child_read_error),
        }
    }
}
async fn commit_readback(
    store: &impl ActivationStore,
    request: ScopeBatchRequest,
    child: ScopeChildKey,
) -> Result<(EffectKey, ScopeBatchOutcome, usize), LocalEffectError> {
    // The post-execution reads cannot replace this check: stale local authority
    // must not submit a new activation, even if it would later withhold a token.
    store.current().await?;
    activation_index(store.stamp(), &request, child)?;
    let outcome = store.execute(&request).await?;
    readback_applied(store, store.stamp(), request, child, outcome).await
}
fn activation_index(
    stamp: &ScopeAuthorityStamp,
    request: &ScopeBatchRequest,
    child: ScopeChildKey,
) -> Result<usize, LocalEffectError> {
    if request.stamp() != stamp {
        return Err(LocalEffectError::WrongRequest);
    }
    request
        .operations()
        .iter()
        .position(|op| op.key() == child && !matches!(op, ScopeChildMutation::Delete { .. }))
        .ok_or(LocalEffectError::WrongRequest)
}
async fn readback_applied(
    store: &impl CurrentChildStore,
    stamp: &ScopeAuthorityStamp,
    request: ScopeBatchRequest,
    child: ScopeChildKey,
    outcome: ScopeBatchOutcome,
) -> Result<(EffectKey, ScopeBatchOutcome, usize), LocalEffectError> {
    let index = activation_index(stamp, &request, child)?;
    if !outcome.matches_request(&request) {
        return Err(LocalEffectError::OutcomeUnknown);
    }
    let revision = *outcome
        .rows()
        .get(index)
        .ok_or(LocalEffectError::OutcomeUnknown)?;
    let key = EffectKey {
        request: Arc::new(request),
        child,
        revision,
        batch_revision: outcome.revision(),
    };
    recheck_record(store, &key).await?;
    Ok((key, outcome, index))
}
async fn recheck_record(
    store: &impl CurrentChildStore,
    key: &EffectKey,
) -> Result<(), LocalEffectError> {
    let row = store.read_current(key.child).await?;
    verify_record(key, row.as_ref())
}

#[cfg(test)]
#[path = "authority_readback_tests.rs"]
mod readback_tests;

/// Independent local backend roles allowed by one committed child activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalEffectUse {
    /// One grouped GTP-U session.
    Gtpu = 1,
    /// One XFRM inbound SA and policy.
    XfrmInbound = 2,
    /// One XFRM outbound SA and policy.
    XfrmOutbound = 4,
    /// One XFRM forward SA and policy.
    XfrmForward = 8,
}

fn consume(state: &AtomicU8, target: LocalEffectUse) -> Result<(), LocalEffectError> {
    let bit = target as u8;
    if state.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
        return Err(LocalEffectError::Stale);
    }
    Ok(())
}

// The durable store retains one terminal outcome per lane. Mirror only its
// payload-free consumption bits, bounded by eight lanes and 64 children per
// outcome. The lifecycle retains this frontier across authority-adapter rebuilds.
// Older states survive solely through callers' still-live tokens.
// No completed request or per-session tombstone is retained by an actor.
#[derive(Default)]
pub(crate) struct Consumption {
    lanes: [Option<ConsumedLane>; opc_session_store::scope_batch::SCOPE_BATCH_LANES],
}
struct ConsumedLane {
    sequence: u64,
    revision: u64,
    children: Vec<Arc<AtomicU8>>,
}
impl Consumption {
    fn child(
        &mut self,
        lane: u8,
        sequence: u64,
        revision: u64,
        children: usize,
        index: usize,
    ) -> Result<Arc<AtomicU8>, LocalEffectError> {
        if children == 0
            || children > opc_session_store::scope_batch::MAX_SCOPE_BATCH_CHILDREN
            || index >= children
            || sequence == 0
        {
            return Err(LocalEffectError::WrongRequest);
        }
        let slot = self
            .lanes
            .get_mut(usize::from(lane))
            .ok_or(LocalEffectError::WrongRequest)?;
        if slot.as_ref().is_some_and(|old| old.sequence > sequence) {
            return Err(LocalEffectError::Stale);
        }
        if slot.as_ref().is_none_or(|old| old.sequence < sequence) {
            *slot = Some(ConsumedLane {
                sequence,
                revision,
                children: (0..children).map(|_| Arc::new(AtomicU8::new(0))).collect(),
            });
        }
        let state = slot.as_ref().ok_or(LocalEffectError::Unavailable)?;
        if state.revision != revision || state.children.len() != children {
            return Err(LocalEffectError::WrongRequest);
        }
        Ok(state.children[index].clone())
    }
}
fn authority_error(error: ScopeAuthorityError) -> LocalEffectError {
    match error {
        ScopeAuthorityError::OutcomeUnknown => LocalEffectError::OutcomeUnknown,
        ScopeAuthorityError::Unavailable => LocalEffectError::Unavailable,
        ScopeAuthorityError::ProfileNotActivated
        | ScopeAuthorityError::Conflict
        | ScopeAuthorityError::ClosureRequired => LocalEffectError::RetryableNoEffect,
        ScopeAuthorityError::StaleAuthority
        | ScopeAuthorityError::Retired
        | ScopeAuthorityError::Superseded => LocalEffectError::Stale,
        _ => LocalEffectError::WrongRequest,
    }
}
fn batch_error(error: ScopeBatchError) -> LocalEffectError {
    match error {
        ScopeBatchError::TransportRevisionMismatch => LocalEffectError::TransportRevisionMismatch,
        ScopeBatchError::OutcomeUnknown => LocalEffectError::OutcomeUnknown,
        ScopeBatchError::Unavailable => LocalEffectError::Unavailable,
        ScopeBatchError::Scope(error) => authority_error(error),
        ScopeBatchError::Conflict(_)
        | ScopeBatchError::RevisionConflict
        | ScopeBatchError::SequenceConflict
        | ScopeBatchError::Cancelled
        | ScopeBatchError::ScopeGuardStalled => LocalEffectError::RetryableNoEffect,
        _ => LocalEffectError::WrongRequest,
    }
}
fn child_read_error(error: ScopeChildReadError) -> LocalEffectError {
    match error {
        ScopeChildReadError::Batch(error) => batch_error(error),
        ScopeChildReadError::TransportRevisionMismatch => {
            LocalEffectError::TransportRevisionMismatch
        }
        ScopeChildReadError::ObservationTooLarge | ScopeChildReadError::ReadBudgetExceeded => {
            LocalEffectError::Unavailable
        }
        _ => LocalEffectError::Unavailable,
    }
}
#[cfg(feature = "native-scope")]
fn rpc_error(error: opc_session_net::scope::ScopeRpcError) -> LocalEffectError {
    use opc_session_net::scope::ScopeRpcError;
    match error {
        ScopeRpcError::TransportRevisionMismatch => LocalEffectError::TransportRevisionMismatch,
        ScopeRpcError::OutcomeUnknown => LocalEffectError::OutcomeUnknown,
        ScopeRpcError::Retry | ScopeRpcError::AuthTimeUnavailable => LocalEffectError::Unavailable,
        ScopeRpcError::Closed | ScopeRpcError::Retired | ScopeRpcError::Superseded => {
            LocalEffectError::Stale
        }
        ScopeRpcError::ProfileUnavailable => LocalEffectError::RetryableNoEffect,
        _ => LocalEffectError::WrongRequest,
    }
}
fn verify_current(
    stamp: &ScopeAuthorityStamp,
    view: &ScopeAuthorityView,
) -> Result<(), LocalEffectError> {
    if !view.is_active()
        || view.stamp() != Some(stamp)
        || view.scope() != stamp.scope()
        || view.revision() != stamp.revision()
        || view.retired_through() >= stamp.incarnation().get()
        || view.admission_generation_floor() != stamp.execution().admission_generation()
    {
        return Err(LocalEffectError::Stale);
    }
    Ok(())
}
fn verify_record(key: &EffectKey, row: Option<&ScopeChildRecord>) -> Result<(), LocalEffectError> {
    let row = row.ok_or(LocalEffectError::Stale)?;
    let operation = key
        .request
        .operations()
        .iter()
        .find(|op| op.key() == key.child)
        .ok_or(LocalEffectError::WrongRequest)?;
    let (value, claims) = match operation {
        ScopeChildMutation::Create { value, claims, .. }
        | ScopeChildMutation::CompareAndSet { value, claims, .. } => (value, claims),
        ScopeChildMutation::Delete { .. } => return Err(LocalEffectError::WrongRequest),
    };
    if row.namespace() != key.request.namespace()
        || row.key() != key.child
        || row.revision() != key.revision
        || row.batch_revision() != key.batch_revision
        || row.value() != Some(value)
        || row.claims() != claims
    {
        return Err(LocalEffectError::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_session_store::scope_authority::{ScopeId, ScopeIncarnation, ScopeNamespace};
    use opc_session_store::{SessionConsensusClusterId, SessionConsumerIdentity};
    use opc_types::{NetworkFunctionKind, TenantId};
    #[test]
    fn retryable_no_effect_results_are_distinct_from_stale_and_changed_requests() {
        for error in [
            ScopeAuthorityError::ProfileNotActivated,
            ScopeAuthorityError::Conflict,
        ] {
            assert_eq!(authority_error(error), LocalEffectError::RetryableNoEffect);
            assert_eq!(
                batch_error(ScopeBatchError::Scope(error)),
                LocalEffectError::RetryableNoEffect
            );
        }
        for error in [
            ScopeBatchError::Conflict(Default::default()),
            ScopeBatchError::RevisionConflict,
            ScopeBatchError::SequenceConflict,
            ScopeBatchError::Cancelled,
            ScopeBatchError::ScopeGuardStalled,
        ] {
            assert_eq!(batch_error(error), LocalEffectError::RetryableNoEffect);
        }
        assert_eq!(
            authority_error(ScopeAuthorityError::Retired),
            LocalEffectError::Stale
        );
        assert_eq!(
            batch_error(ScopeBatchError::IdempotencyConflict),
            LocalEffectError::WrongRequest
        );
        assert_eq!(
            batch_error(ScopeBatchError::OutcomeUnknown),
            LocalEffectError::OutcomeUnknown
        );
        assert_eq!(
            batch_error(ScopeBatchError::Unavailable),
            LocalEffectError::Unavailable
        );
    }
    #[test]
    fn consumption_is_shared_by_recovered_tokens_and_separate_for_roles_and_children() {
        let mut consumption = Consumption::default();
        let first = consumption.child(0, 1, 1, 2, 0).unwrap();
        consume(&first, LocalEffectUse::XfrmInbound).unwrap();
        let recovered = consumption.child(0, 1, 1, 2, 0).unwrap();
        assert!(Arc::ptr_eq(&first, &recovered));
        assert_eq!(
            consume(&recovered, LocalEffectUse::XfrmInbound),
            Err(LocalEffectError::Stale)
        );
        consume(&recovered, LocalEffectUse::XfrmOutbound).unwrap();
        consume(&recovered, LocalEffectUse::XfrmForward).unwrap();
        consume(&recovered, LocalEffectUse::Gtpu).unwrap();
        let sibling = consumption.child(0, 1, 1, 2, 1).unwrap();
        consume(&sibling, LocalEffectUse::Gtpu).unwrap();
        assert!(consumption.child(0, 1, 2, 2, 0).is_err());
        assert!(consumption.child(0, 1, 1, 3, 0).is_err());
        assert!(consumption.child(8, 1, 1, 2, 0).is_err());
        assert!(consumption.child(0, 1, 1, 65, 0).is_err());
    }

    #[test]
    fn consumption_churn_keeps_only_fixed_lane_frontiers_and_live_token_bits() {
        let mut consumption = Consumption::default();
        let old = consumption.child(0, 1, 1, 1, 0).unwrap();
        consume(&old, LocalEffectUse::Gtpu).unwrap();
        for sequence in 2..10_000 {
            for lane in 0..8 {
                let token = consumption.child(lane, sequence, sequence, 64, 63).unwrap();
                consume(&token, LocalEffectUse::Gtpu).unwrap();
                assert_eq!(Arc::strong_count(&token), 2);
                let states = consumption
                    .lanes
                    .iter()
                    .flatten()
                    .map(|slot| slot.children.len())
                    .sum::<usize>();
                assert!(
                    states <= 8 * 64,
                    "past activations never increase retained state or search work"
                );
            }
        }
        assert_eq!(
            Arc::strong_count(&old),
            1,
            "only the caller retains an old activation's bits"
        );
        assert_eq!(
            consume(&old, LocalEffectUse::Gtpu),
            Err(LocalEffectError::Stale)
        );
        assert!(consumption.child(0, 1, 1, 1, 0).is_err());
    }
    #[test]
    fn closed_stale_or_retired_claims_cannot_pass_current_execution_check() {
        let cluster = SessionConsensusClusterId::new("local").unwrap();
        let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap();
        let identity = opc_session_store::SessionConsensusIdentity::new(
            cluster,
            opc_consensus::derive_configuration_id(cluster, epoch, &[[1; 32]]),
            epoch,
        );
        let scope = ScopeId::new(
            identity,
            TenantId::from_static("local"),
            NetworkFunctionKind::smf(),
            [1; 32],
        )
        .unwrap();
        let execution = ScopeExecution::new(
            SessionConsumerIdentity::new("spiffe://test/worker").unwrap(),
            1,
            [1; 16],
            [2; 16],
            [3; 32],
        )
        .unwrap();
        // These are explicitly untrusted serialized observations. They never
        // construct CommittedScopeAuthority or a CommittedScopeEffect.
        let stamp: ScopeAuthorityStamp = serde_json::from_value(serde_json::json!({
            "namespace": ScopeNamespace::new(scope.clone(), ScopeIncarnation::new(1).unwrap()).unwrap(), "revision": 1, "execution": execution,
        })).unwrap();
        let base = serde_json::json!({"scope": scope, "revision": 1, "retired_through": 0, "admission_generation_floor": 1,
            "stamp": stamp, "active": true, "closed_digest": null });
        verify_current(&stamp, &serde_json::from_value(base.clone()).unwrap()).unwrap();
        for field in [
            "active",
            "retired_through",
            "stamp",
            "revision",
            "admission_generation_floor",
        ] {
            let mut changed = base.clone();
            changed[field] = match field {
                "active" => false.into(),
                "stamp" => serde_json::Value::Null,
                _ => 2.into(),
            };
            let view = serde_json::from_value(changed).unwrap();
            assert!(
                verify_current(&stamp, &view).is_err(),
                "changed {field} was accepted"
            );
        }
    }
}
