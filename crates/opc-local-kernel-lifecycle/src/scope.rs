use crate::reset::{self, ResetPort};
use crate::{LocalLifecycleError as Error, ResetPhase};
use async_trait::async_trait;
use opc_linux_gtpu_sys::tc::{
    retire_artifacts_checked, ArtifactInventory, ArtifactSpec, ContainedScope,
    ContainmentInspection, LocalKernelScope, LocalScopeSpec, RetiredArtifact, TcHook,
};
use opc_route_steering::{OwnedRouteRuleScope, OwnedRouteRuleSet, RouteSteeringBackend};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{oneshot, OwnedRwLockReadGuard, RwLock};

#[cfg(feature = "store")]
mod activation;
#[cfg(all(test, target_os = "linux", feature = "store"))]
mod activation_tests;
mod rebuild;
mod residue;
#[cfg(feature = "store")]
pub use activation::KernelCompletion;

/// Backend-owned current-image policy. Implementations must inspect permanent
/// selector/recovery history before returning a resettable graph. The common
/// coordinator never derives artifact ownership from caller-supplied names.
pub trait LocalArtifact: Send + Sync + std::fmt::Debug {
    /// The complete embedded-image catalog for this one graph.
    fn artifact(&self) -> &ArtifactSpec;
    /// Backend control-directory inodes to preserve. Every listed directory
    /// must be empty; permanent recovery history prevents local reset.
    fn preserved_empty_directories(&self) -> Vec<std::path::PathBuf> {
        Vec::new()
    }
    /// Inspect through the held local scope without changing kernel state.
    fn inspect(&self, scope: &LocalKernelScope) -> Result<ArtifactInventory, Error>;
}

/// The namespace actor that owns every XFRM producer in this local scope.
/// A backend implementation must preserve its exclusive-reset preconditions.
#[async_trait]
pub trait LocalXfrmReset: Send + Sync {
    /// The same acquired writer guard used by the other local backends.
    fn local_scope(&self) -> &LocalKernelScope;
    /// Fresh complete SPD/SAD readback. Failure never means empty.
    async fn is_empty(&self) -> Result<bool, Error>;
    /// Reset a stopped, wholly owned namespace, checking containment before
    /// each protective deletion and freshly verifying both tables afterwards.
    async fn reset_contained(&self, contained: &ContainedScope) -> Result<(), Error>;
}

/// Consumer-owned device and socket-policy lifecycle. The implementation is
/// responsible for declaring every plaintext egress and verifying completion;
/// returning success from a delete ACK alone does not satisfy this contract.
#[async_trait]
pub trait LocalCompanionReset: Send + Sync {
    /// The acquired local guard retained through all companion effects.
    fn local_scope(&self) -> &LocalKernelScope;
    /// Every interface through which these companions can emit plaintext.
    fn plaintext_egresses(&self) -> &[u32];
    /// Fresh, complete absence readback for the declared companions.
    async fn is_empty(&self) -> Result<bool, Error>;
    /// Retire the consumer's declared effects and verify their absence.
    async fn reset_contained(&self, contained: &ContainedScope) -> Result<(), Error>;
}

/// Explicit deployment assertion that this scope owns no companion devices
/// or per-socket policies. It makes no assertion about namespace SPD/SAD.
pub struct NoLocalCompanions {
    scope: LocalKernelScope,
}
impl NoLocalCompanions {
    /// Declare that no consumer-owned companion effects exist in this scope.
    pub fn new(scope: LocalKernelScope) -> Self {
        Self { scope }
    }
}
#[async_trait]
impl LocalCompanionReset for NoLocalCompanions {
    fn local_scope(&self) -> &LocalKernelScope {
        &self.scope
    }
    fn plaintext_egresses(&self) -> &[u32] {
        &[]
    }
    async fn is_empty(&self) -> Result<bool, Error> {
        self.scope.verify()?;
        Ok(true)
    }
    async fn reset_contained(&self, contained: &ContainedScope) -> Result<(), Error> {
        same_scope(&self.scope, contained.scope())?;
        contained.recheck()?;
        Ok(())
    }
}

/// Already-bound owners composed by a reset. Route reconciliation uses the
/// existing collection API, on a dedicated thread inheriting this namespace.
pub struct LocalResetParticipants {
    xfrm: Arc<dyn LocalXfrmReset>,
    routes: Arc<dyn RouteSteeringBackend>,
    companions: Arc<dyn LocalCompanionReset>,
}
impl LocalResetParticipants {
    /// Assemble the native XFRM actor, route backend and declared companions.
    pub fn new(
        xfrm: Arc<dyn LocalXfrmReset>,
        routes: Arc<dyn RouteSteeringBackend>,
        companions: Arc<dyn LocalCompanionReset>,
    ) -> Self {
        Self {
            xfrm,
            routes,
            companions,
        }
    }
}

#[derive(Default)]
struct State {
    epoch: u64,
    retired: Option<u64>,
    rebuilding: BTreeSet<usize>,
    graphs: BTreeMap<usize, Arc<opc_linux_gtpu_sys::tc::InstalledArtifact>>,
    #[cfg(feature = "store")]
    opened: Option<activation::PublishedOpening>,
}
struct Inner {
    #[cfg(all(test, target_os = "linux", feature = "store"))]
    open_fault: Mutex<Option<activation::TestFault>>,
    scope: LocalKernelScope,
    artifacts: Vec<Arc<dyn LocalArtifact>>,
    layout: crate::layout::Layout,
    routes: Vec<OwnedRouteRuleScope>,
    egresses: BTreeSet<u32>,
    barrier: Arc<RwLock<()>>,
    state: Mutex<State>,
    xfrm_actor: AtomicBool,
    #[cfg(feature = "store")]
    effect_owner: AtomicBool,
    #[cfg(feature = "store")]
    consumption: Mutex<crate::authority::Consumption>,
    #[cfg(feature = "store")]
    effect_closed: AtomicBool,
    #[cfg(feature = "store")]
    opening: Arc<tokio::sync::Mutex<()>>,
    cleanup: Mutex<Vec<Weak<Mutex<crate::CleanupSchedule>>>>,
    graph_actors: Mutex<BTreeSet<usize>>,
}

// A held native guard has exactly one barrier. Keeping weak entries does not
// prolong an abandoned lifecycle; construction prunes all expired entries.
static COORDINATORS: Mutex<Vec<Weak<Inner>>> = Mutex::new(Vec::new());

/// Affine registration of the sole XFRM producer in this coordinator.
/// The namespace actor retains it until its admitted work drains and it exits.
/// This is local producer exclusion, not store or session authority.
pub struct LocalXfrmActorRegistration {
    lifecycle: LocalKernelLifecycle,
}
impl Drop for LocalXfrmActorRegistration {
    fn drop(&mut self) {
        self.lifecycle
            .inner
            .xfrm_actor
            .store(false, Ordering::Release);
    }
}

/// Shared process-lifetime exclusion and stopped-scope reset barrier.
///
/// Every bound backend holds this same coordinator. Reset takes its exclusive
/// barrier before inspection; rebuilding holds a shared guard. There is no
/// persistent object journal, store authority, or clock-based ownership here.
#[derive(Clone)]
pub struct LocalKernelLifecycle {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for LocalKernelLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalKernelLifecycle")
    }
}

fn validate_plan(
    spec: &LocalScopeSpec,
    artifacts: &[&ArtifactSpec],
    routes: &[OwnedRouteRuleScope],
    egresses: &[u32],
) -> Result<(), Error> {
    if artifacts.len() > 64 || routes.len() > 64 || egresses.is_empty() || egresses.len() > 32 {
        return Err(Error::InvalidPlan);
    }
    let declared = egresses.iter().copied().collect::<BTreeSet<_>>();
    if declared.len() != egresses.len()
        || declared.contains(&0)
        || declared.iter().any(|index| {
            !spec
                .hooks()
                .iter()
                .any(|hook| hook.ifindex() == *index && hook.hook() == TcHook::Egress)
        })
        || routes
            .iter()
            .any(|route| !declared.contains(&route.output_interface()))
        || routes.iter().copied().collect::<BTreeSet<_>>().len() != routes.len()
    {
        return Err(Error::InvalidPlan);
    }
    let mut slots = BTreeSet::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        if artifact.slots().any(|slot| !slots.insert(slot))
            || artifacts[..index].iter().any(|other| {
                artifact.directory().starts_with(other.directory())
                    || other.directory().starts_with(artifact.directory())
            })
        {
            return Err(Error::InvalidPlan);
        }
    }
    if slots != spec.data_slots().iter().copied().collect() {
        return Err(Error::InvalidPlan);
    }
    Ok(())
}

impl LocalKernelLifecycle {
    /// Bind all GTP-U/DSCP catalogs and owned route collections to one guard.
    /// `plaintext_egresses` includes every possible XFRM plaintext egress,
    /// whether DSCP is enabled there or not. This is a deployment assertion.
    pub fn new(
        scope: LocalKernelScope,
        artifacts: Vec<Arc<dyn LocalArtifact>>,
        routes: Vec<OwnedRouteRuleScope>,
        plaintext_egresses: Vec<u32>,
    ) -> Result<Self, Error> {
        validate_plan(
            scope.spec(),
            &artifacts
                .iter()
                .map(|value| value.artifact())
                .collect::<Vec<_>>(),
            &routes,
            &plaintext_egresses,
        )?;
        scope.verify()?;
        let layout = crate::layout::Layout::new(&artifacts)?;
        let mut coordinators = COORDINATORS.lock().map_err(|_| Error::Indeterminate)?;
        coordinators.retain(|entry| entry.strong_count() != 0);
        if coordinators
            .iter()
            .filter_map(Weak::upgrade)
            .any(|entry| entry.scope.is_same_instance(&scope))
        {
            return Err(Error::InvalidPlan);
        }
        let lifecycle = Self {
            inner: Arc::new(Inner {
                #[cfg(all(test, target_os = "linux", feature = "store"))]
                open_fault: Mutex::new(None),
                scope,
                artifacts,
                layout,
                routes,
                egresses: plaintext_egresses.into_iter().collect(),
                barrier: Arc::new(RwLock::new(())),
                state: Mutex::new(State::default()),
                xfrm_actor: AtomicBool::new(false),
                #[cfg(feature = "store")]
                effect_owner: AtomicBool::new(false),
                #[cfg(feature = "store")]
                consumption: Mutex::default(),
                #[cfg(feature = "store")]
                effect_closed: AtomicBool::new(false),
                #[cfg(feature = "store")]
                opening: Arc::new(tokio::sync::Mutex::new(())),
                cleanup: Mutex::new(Vec::new()),
                graph_actors: Mutex::new(BTreeSet::new()),
            }),
        };
        coordinators.push(Arc::downgrade(&lifecycle.inner));
        Ok(lifecycle)
    }
    /// The retained native writer guard, without any activation authority.
    pub fn local_scope(&self) -> &LocalKernelScope {
        &self.inner.scope
    }
    fn cleanup_watch(&self) -> Result<Arc<Mutex<crate::CleanupSchedule>>, Error> {
        let watch = Arc::new(Mutex::new(crate::CleanupSchedule::default()));
        let mut cleanup = self
            .inner
            .cleanup
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        cleanup.retain(|entry| entry.strong_count() != 0);
        cleanup.push(Arc::downgrade(&watch));
        Ok(watch)
    }
    /// Identifier-free progress of active scope opening/reset/rebuild cleanup.
    /// The first failure's age continues increasing between automatic retries.
    pub fn cleanup_progress(&self) -> Result<Vec<crate::CleanupProgress>, Error> {
        let mut cleanup = self
            .inner
            .cleanup
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        cleanup.retain(|entry| entry.strong_count() != 0);
        cleanup
            .iter()
            .filter_map(Weak::upgrade)
            .map(|watch| {
                watch
                    .lock()
                    .map_err(|_| Error::Indeterminate)
                    .map(|schedule| schedule.progress())
            })
            .collect()
    }
    /// Reserve the single namespace actor before it can accept any command.
    /// A second producer is refused even when it declares the same scope.
    pub fn register_xfrm_actor(&self) -> Result<LocalXfrmActorRegistration, Error> {
        self.local_scope().verify()?;
        self.inner
            .xfrm_actor
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidPlan)?;
        Ok(LocalXfrmActorRegistration {
            lifecycle: self.clone(),
        })
    }
    #[cfg(feature = "store")]
    pub(crate) fn register_effect_owner(&self) -> Result<LocalEffectOwner, Error> {
        self.local_scope().verify()?;
        if self.effects_closed() {
            return Err(Error::Stale);
        }
        self.inner
            .effect_owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidPlan)?;
        Ok(LocalEffectOwner(self.clone()))
    }
    #[cfg(feature = "store")]
    pub(crate) fn effect_consumption(&self) -> &Mutex<crate::authority::Consumption> {
        &self.inner.consumption
    }
    #[cfg(feature = "store")]
    pub(crate) fn effects_closed(&self) -> bool {
        self.inner.effect_closed.load(Ordering::Acquire)
    }
    #[cfg(feature = "store")]
    pub(crate) fn close_effects(&self) {
        self.inner.effect_closed.store(true, Ordering::Release);
    }
    #[cfg(feature = "store")]
    pub(crate) async fn drain_operations(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        self.inner.barrier.clone().write_owned().await
    }
    #[cfg(feature = "store")]
    pub(crate) fn current_effect_epoch(&self) -> Result<LocalScopeEpoch, Error> {
        self.local_scope().verify()?;
        let state = self.inner.state.lock().map_err(|_| Error::Indeterminate)?;
        if state.retired != Some(state.epoch) {
            return Err(Error::Stale);
        }
        Ok(LocalScopeEpoch {
            lifecycle: self.clone(),
            epoch: state.epoch,
        })
    }
    /// Bind a backend to an exact registered catalog. A lookalike coordinator
    /// with the same path strings cannot use this binding or its receipts.
    pub fn bind_graph(&self, artifact: &ArtifactSpec) -> Result<LocalGraphBinding, Error> {
        let index = self
            .inner
            .artifacts
            .iter()
            .position(|value| value.artifact() == artifact)
            .ok_or(Error::InvalidPlan)?;
        Ok(LocalGraphBinding {
            lifecycle: self.clone(),
            index,
        })
    }
    fn participants(&self, participants: &LocalResetParticipants) -> Result<(), Error> {
        same_scope(self.local_scope(), participants.xfrm.local_scope())?;
        same_scope(self.local_scope(), participants.companions.local_scope())?;
        if participants
            .companions
            .plaintext_egresses()
            .iter()
            .any(|index| !self.inner.egresses.contains(index))
        {
            return Err(Error::InvalidPlan);
        }
        Ok(())
    }
    /// Authorize disruption and retire every declared predecessor effect.
    ///
    /// Cancellation before the exclusive barrier is acquired has no effects.
    /// Once admitted, a dedicated namespace thread owns the operation and its
    /// guard until readback finishes, even if the observer is dropped. After
    /// effect-free preflight, bounded attempts automatically retry with fresh
    /// inventory and backoff; uncertainty never yields a rebuild receipt.
    /// An unsupported TCX query returns [`Error::Unsupported`] immediately,
    /// before containment writes, instead of retrying an unavailable capability.
    pub async fn reset(
        &self,
        participants: LocalResetParticipants,
    ) -> Result<LocalScopeResetReceipt, Error> {
        self.participants(&participants)?;
        self.local_scope().verify()?;
        let barrier = self.inner.barrier.clone().write_owned().await;
        self.local_scope().verify()?;
        let watch = self.cleanup_watch()?;
        let lifecycle = self.clone();
        bound_thread(move || {
            let _barrier = barrier;
            lifecycle.local_scope().verify()?;
            let epoch = {
                let mut state = lifecycle
                    .inner
                    .state
                    .lock()
                    .map_err(|_| Error::Indeterminate)?;
                state.epoch = state.epoch.checked_add(1).ok_or(Error::Indeterminate)?;
                state.retired = None;
                state.rebuilding.clear();
                state.graphs.clear();
                #[cfg(feature = "store")]
                {
                    state.opened = None;
                }
                state.epoch
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|_| Error::Indeterminate)?;
            let mut port = NativeReset {
                lifecycle: lifecycle.clone(),
                participants,
                inventories: Vec::new(),
                contained: None,
                retired: Vec::new(),
                attempt: None,
                residue: residue::Residue::default(),
            };
            runtime.block_on(reset::supervise(&mut port, &watch))?;
            lifecycle
                .inner
                .state
                .lock()
                .map_err(|_| Error::Indeterminate)?
                .retired = Some(epoch);
            Ok(LocalScopeResetReceipt {
                lifecycle,
                epoch,
                contained: port.contained.ok_or(Error::Indeterminate)?,
                residue: Arc::new(Mutex::new(port.residue.observed())),
            })
        })
        .await
    }
    /// Inspect the complete local scope before admission, without changing
    /// qdiscs, filters, pins, XFRM, routes or companions. Every covered hook gets
    /// a TCX/topology query, including an empty scope with no clsact qdisc.
    ///
    /// An owned partial predecessor bank returns
    /// [`LocalScopeInspection::OwnedPartialContainment`], not a failure to retry
    /// before admission. Repair still requires an explicitly authorized reset.
    /// Missing capabilities return [`Error::Unsupported`]. This call makes one
    /// inspection attempt and grants no startup, rebuild or effect authority.
    /// Preserved foreign filters are diagnostic only: an otherwise empty owned
    /// scope still reports [`LocalScopeInspection::Empty`].
    ///
    /// This is an owner-process call using its already-held [`LocalKernelScope`]
    /// and exclusive file lock. A second process opening that scope gets
    /// [`opc_linux_gtpu_sys::tc::ScopeError::Busy`]; an inspector holding the
    /// lock likewise makes the owner's open return `Busy` until it releases it.
    pub async fn inspect_scope(
        &self,
        participants: LocalResetParticipants,
    ) -> Result<LocalScopeInspectionResult, Error> {
        self.participants(&participants)?;
        let barrier = self.inner.barrier.clone().write_owned().await;
        self.local_scope().verify()?;
        let lifecycle = self.clone();
        bound_thread(move || {
            let _barrier = barrier;
            let tc = lifecycle.local_scope().inspect()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|_| Error::Indeterminate)?;
            let mut port = NativeReset {
                lifecycle: lifecycle.clone(),
                participants,
                inventories: Vec::new(),
                contained: None,
                retired: Vec::new(),
                attempt: None,
                residue: residue::Residue::default(),
            };
            port.inspect()?;
            let empty = runtime.block_on(port.empty())?;
            lifecycle.local_scope().verify()?;
            Ok(LocalScopeInspectionResult::new(
                tc.containment(),
                empty,
                tc.foreign_filters_present(),
            ))
        })
        .await
    }
    /// Observe an empty data scope without installing containment filters.
    /// Remaining verified exit-time filters report a contained startup state.
    /// A nonempty predecessor returns `None`, and needs authorized containment
    /// and reset before it can supply startup or rebuild evidence.
    pub async fn observe_empty(
        &self,
        participants: LocalResetParticipants,
    ) -> Result<Option<LocalStartupObservation>, Error> {
        self.participants(&participants)?;
        let barrier = self.inner.barrier.clone().write_owned().await;
        self.local_scope().verify()?;
        let lifecycle = self.clone();
        bound_thread(move || {
            let _barrier = barrier;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|_| Error::Indeterminate)?;
            let mut port = NativeReset {
                lifecycle: lifecycle.clone(),
                participants,
                inventories: Vec::new(),
                contained: None,
                retired: Vec::new(),
                attempt: None,
                residue: residue::Residue::default(),
            };
            port.inspect()?;
            let empty = runtime.block_on(port.empty())?;
            let state = if empty && lifecycle.local_scope().containment_present()? {
                LocalStartupState::ExclusionHeldAndContained
            } else {
                LocalStartupState::ExclusionHeldAndEmpty
            };
            lifecycle.local_scope().verify()?;
            Ok(empty.then_some(LocalStartupObservation { lifecycle, state }))
        })
        .await
    }
}

#[cfg(feature = "store")]
pub(crate) struct LocalEffectOwner(LocalKernelLifecycle);
#[cfg(feature = "store")]
impl Drop for LocalEffectOwner {
    fn drop(&mut self) {
        self.0.inner.effect_owner.store(false, Ordering::Release);
    }
}

fn same_scope(expected: &LocalKernelScope, actual: &LocalKernelScope) -> Result<(), Error> {
    if expected.is_same_instance(actual) {
        Ok(())
    } else {
        Err(Error::InvalidPlan)
    }
}
async fn bound_thread<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let (sent, received) = oneshot::channel();
    std::thread::Builder::new()
        .name("opc-local-reset".to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or(Err(Error::Indeterminate));
            let _ = sent.send(result);
        })
        .map_err(|_| Error::Indeterminate)?;
    received.await.map_err(|_| Error::Indeterminate)?
}

/// Opaque binding of one backend's catalog to its shared coordinator.
#[derive(Clone, Debug)]
pub struct LocalGraphBinding {
    lifecycle: LocalKernelLifecycle,
    index: usize,
}
/// Affine registration of one backend producer for a declared graph.
/// Clones of that backend share this registration through their inner owner.
pub struct LocalGraphActorRegistration {
    binding: LocalGraphBinding,
}
impl Drop for LocalGraphActorRegistration {
    fn drop(&mut self) {
        if let Ok(mut actors) = self.binding.lifecycle.inner.graph_actors.lock() {
            actors.remove(&self.binding.index);
        }
    }
}
impl LocalGraphBinding {
    /// Reserve this graph's sole backend producer for its actual lifetime.
    pub fn register_actor(&self) -> Result<LocalGraphActorRegistration, Error> {
        self.local_scope().verify()?;
        if !self
            .lifecycle
            .inner
            .graph_actors
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .insert(self.index)
        {
            return Err(Error::InvalidPlan);
        }
        Ok(LocalGraphActorRegistration {
            binding: self.clone(),
        })
    }
    /// The same held native guard retained by every scoped backend.
    pub fn local_scope(&self) -> &LocalKernelScope {
        self.lifecycle.local_scope()
    }
    /// Exact registered artifact, derived by the owning backend.
    pub fn artifact(&self) -> &ArtifactSpec {
        self.lifecycle.inner.artifacts[self.index].artifact()
    }
    /// Enter one fresh graph build only after all backends retired. This is
    /// structural rebuild permission under containment, not serving authority.
    pub async fn begin_rebuild(
        &self,
        receipt: &LocalScopeResetReceipt,
    ) -> Result<LocalRebuildGuard, Error> {
        if !Arc::ptr_eq(&self.lifecycle.inner, &receipt.lifecycle.inner) {
            return Err(Error::Stale);
        }
        let barrier = self.lifecycle.inner.barrier.clone().read_owned().await;
        receipt.contained.recheck()?;
        self.lifecycle.inner.layout.verify(self.local_scope())?;
        let inventory = self.lifecycle.inner.artifacts[self.index].inspect(self.local_scope())?;
        if !inventory.is_locally_empty() {
            return Err(Error::Stale);
        }
        let watch = self.lifecycle.cleanup_watch()?;
        let mut state = self
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.retired != Some(receipt.epoch)
            || state.epoch != receipt.epoch
            || !state.rebuilding.insert(self.index)
        {
            return Err(Error::Stale);
        }
        Ok(LocalRebuildGuard {
            binding: self.clone(),
            epoch: receipt.epoch,
            contained: receipt.contained.clone(),
            barrier: Some(barrier),
            attempt: Mutex::new(None),
            watch,
        })
    }
}

/// Holds the exclusive-reset barrier open for one contained structural build.
/// It cannot authorize candidate SAs, active sessions or containment opening.
pub struct LocalRebuildGuard {
    binding: LocalGraphBinding,
    epoch: u64,
    contained: ContainedScope,
    barrier: Option<OwnedRwLockReadGuard<()>>,
    attempt: Mutex<Option<crate::CleanupAttempt>>,
    watch: Arc<Mutex<crate::CleanupSchedule>>,
}
impl LocalRebuildGuard {
    /// Attach one loaded artifact program under fresh containment. Only this
    /// graph's declared coordinates are available; it cannot replace a slot.
    pub fn attach_program(
        &self,
        slot: opc_linux_gtpu_sys::tc::TcSlot,
        program: &opc_linux_gtpu_sys::bpf::ProgramHandle,
        name: &str,
    ) -> Result<(), Error> {
        self.recheck()?;
        if !self.artifact().slots().any(|declared| declared == slot) {
            return Err(Error::InvalidPlan);
        }
        self.contained.attach_data(slot, program, name)?;
        self.recheck()
    }
    /// Publish structural readiness only after a complete fresh catalog/FD
    /// comparison. This still grants no session activation or opening authority.
    pub fn complete(
        &self,
        programs: Vec<opc_linux_gtpu_sys::bpf::ProgramHandle>,
        maps: Vec<opc_linux_gtpu_sys::bpf::MapHandle>,
    ) -> Result<LocalInstalledGraph, Error> {
        self.recheck()?;
        let artifact = &self.binding.lifecycle.inner.artifacts[self.binding.index];
        let installed = Arc::new(
            artifact
                .inspect(self.local_scope())?
                .into_installed(programs, maps)?,
        );
        installed.recheck()?;
        self.recheck()?;
        let mut state = self
            .binding
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.graphs.contains_key(&self.binding.index)
            || !state.rebuilding.remove(&self.binding.index)
        {
            return Err(Error::Stale);
        }
        state.graphs.insert(self.binding.index, installed.clone());
        Ok(LocalInstalledGraph {
            epoch: LocalScopeEpoch {
                lifecycle: self.binding.lifecycle.clone(),
                epoch: self.epoch,
            },
            installed,
        })
    }
    /// Retire a failed partial structural build under held containment. A
    /// completed graph cannot enter this path; it belongs to ordered reset.
    pub fn retire_partial(&self) -> Result<(), Error> {
        self.recheck()?;
        if self
            .binding
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .graphs
            .contains_key(&self.binding.index)
        {
            return Err(Error::Stale);
        }
        let artifact = &self.binding.lifecycle.inner.artifacts[self.binding.index];
        let retired = retire_artifacts_checked(
            vec![artifact.inspect(self.local_scope())?],
            &self.contained,
            || {
                self.recheck()
                    .map_err(|_| opc_linux_gtpu_sys::tc::ScopeError::Inspection)
            },
        )?;
        for artifact in retired {
            artifact.local().recheck()?;
        }
        if !artifact.inspect(self.local_scope())?.is_locally_empty() {
            return Err(Error::Indeterminate);
        }
        self.binding
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .rebuilding
            .remove(&self.binding.index);
        Ok(())
    }
    /// Create the declared private graph leaf through retained descriptors.
    /// No legacy lock tree or absolute-path create-or-adopt loader is used.
    pub fn pin_directory(&self) -> Result<opc_linux_gtpu_sys::tc::PinDirectory, Error> {
        self.recheck()?;
        self.contained
            .ensure_pin_directory(self.artifact().directory())
            .map_err(Into::into)
    }
    /// Recheck the held scope, containment and still-current local reset epoch.
    pub fn recheck(&self) -> Result<(), Error> {
        if self
            .attempt
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .as_ref()
            .is_some_and(|attempt| !attempt.has_budget())
        {
            return Err(Error::Indeterminate);
        }
        self.contained.recheck()?;
        let state = self
            .binding
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.retired != Some(self.epoch) || state.epoch != self.epoch {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Exact graph admitted for this contained build.
    pub fn artifact(&self) -> &ArtifactSpec {
        self.binding.artifact()
    }
    /// Retained native guard. Pin mutations must remain descriptor-relative.
    pub fn local_scope(&self) -> &LocalKernelScope {
        self.binding.local_scope()
    }
}

/// Retained process-local identity of one fresh, complete structural graph.
/// It stays valid through opening and becomes stale at the next ordered reset.
#[derive(Clone)]
pub struct LocalInstalledGraph {
    epoch: LocalScopeEpoch,
    installed: Arc<opc_linux_gtpu_sys::tc::InstalledArtifact>,
}
impl std::fmt::Debug for LocalInstalledGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalInstalledGraph")
    }
}
impl LocalInstalledGraph {
    /// Whether both receipts retain the same exact graph publication.
    pub fn is_same(&self, other: &Self) -> bool {
        self.epoch.is_same(&other.epoch) && Arc::ptr_eq(&self.installed, &other.installed)
    }
    /// Whether this process-local graph was published in the supplied reset.
    pub fn matches_reset(&self, reset: &LocalScopeResetReceipt) -> bool {
        Arc::ptr_eq(&self.epoch.lifecycle.inner, &reset.lifecycle.inner)
            && self.epoch.epoch == reset.epoch
    }
    /// The reset epoch retained by this graph. It carries no store authority.
    pub fn epoch(&self) -> LocalScopeEpoch {
        self.epoch.clone()
    }
    /// Verify the unchanged local epoch, exact graph and held descriptors.
    pub fn recheck(&self) -> Result<(), Error> {
        self.epoch.recheck()?;
        self.installed.recheck()?;
        self.epoch.recheck()
    }
    /// Admit a local operation under the reset barrier. The operation still
    /// needs committed activation before every new forwarding mutation.
    pub async fn begin_operation(&self) -> Result<LocalOperation, Error> {
        let guard = self.epoch.begin_operation().await?;
        self.recheck()?;
        Ok(guard)
    }
}

/// Combined local retirement, kept separate from global object-release counts.
#[derive(Clone)]
pub struct LocalScopeResetReceipt {
    lifecycle: LocalKernelLifecycle,
    epoch: u64,
    contained: ContainedScope,
    residue: Arc<Mutex<residue::Residue>>,
}
impl std::fmt::Debug for LocalScopeResetReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalScopeResetReceipt")
    }
}
impl LocalScopeResetReceipt {
    /// Hold the reset barrier while a backend performs a contained operation.
    /// This permits structural work and a noncandidate capability probe only;
    /// it does not authorize any session, SA activation or containment opening.
    pub async fn begin_contained_operation(
        &self,
        lifecycle: &LocalKernelLifecycle,
    ) -> Result<LocalContainedOperation, Error> {
        if !Arc::ptr_eq(&self.lifecycle.inner, &lifecycle.inner) {
            return Err(Error::Stale);
        }
        let barrier = lifecycle.inner.barrier.clone().read_owned().await;
        let epoch = LocalScopeEpoch {
            lifecycle: lifecycle.clone(),
            epoch: self.epoch,
        };
        epoch.recheck()?;
        self.contained.recheck()?;
        Ok(LocalContainedOperation {
            epoch,
            contained: self.contained.clone(),
            _barrier: barrier,
        })
    }
    /// Recheck containment and retain the scope for transport-bound startup.
    /// This observation does not mint a boot ticket or execution generation.
    pub fn startup_observation(&self) -> Result<LocalStartupObservation, Error> {
        self.contained.recheck()?;
        let state = self
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.epoch != self.epoch || state.retired != Some(self.epoch) {
            return Err(Error::Stale);
        }
        Ok(LocalStartupObservation {
            lifecycle: self.lifecycle.clone(),
            state: LocalStartupState::ExclusionHeldAndContained,
        })
    }
    /// Fixed lower bound of observed old IDs whose release is unproven;
    /// harmless detached object FDs never gate rebuild.
    pub fn residue_count(&self) -> Result<usize, Error> {
        Ok(self
            .residue
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .count())
    }
    /// Return retained release uncertainty without reopening node-global IDs.
    /// Closing an outside descriptor or waiting cannot prove global absence.
    pub fn observe_release(&self) -> Result<usize, Error> {
        let mut residue = self.residue.lock().map_err(|_| Error::Indeterminate)?;
        residue.observe();
        Ok(residue.count())
    }
}

/// Process-local binding to one completed reset. Another reset invalidates it.
/// It carries no durable authority and cannot independently authorize effects.
#[derive(Clone)]
pub struct LocalScopeEpoch {
    lifecycle: LocalKernelLifecycle,
    epoch: u64,
}
impl LocalScopeEpoch {
    /// Attempt local admission without blocking the namespace actor behind a
    /// reset that itself needs that actor. `None` means ordinary backpressure.
    pub fn try_begin_operation(&self) -> Result<Option<LocalOperation>, Error> {
        self.recheck()?;
        let Ok(barrier) = self.lifecycle.inner.barrier.clone().try_read_owned() else {
            return Ok(None);
        };
        self.recheck()?;
        Ok(Some(LocalOperation {
            epoch: self.clone(),
            _barrier: barrier,
        }))
    }
    /// Hold the reset barrier for a scoped effect. Store authority is separate.
    pub async fn begin_operation(&self) -> Result<LocalOperation, Error> {
        let barrier = self.lifecycle.inner.barrier.clone().read_owned().await;
        self.recheck()?;
        Ok(LocalOperation {
            epoch: self.clone(),
            _barrier: barrier,
        })
    }
    /// Refuse a replaced guard or any intervening reset, successful or partial.
    pub fn recheck(&self) -> Result<(), Error> {
        self.lifecycle.local_scope().verify()?;
        let state = self
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.epoch != self.epoch || state.retired != Some(self.epoch) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Whether two observations name the same coordinator and reset attempt.
    pub fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.lifecycle.inner, &other.lifecycle.inner) && self.epoch == other.epoch
    }
}

/// Held local writer/reset exclusion for one supervised effect.
pub struct LocalOperation {
    epoch: LocalScopeEpoch,
    _barrier: OwnedRwLockReadGuard<()>,
}
impl LocalOperation {
    /// Recheck the native guard and epoch immediately before a local effect.
    pub fn recheck(&self) -> Result<(), Error> {
        self.epoch.recheck()
    }
    /// Exact coordinator/reset observation used by this operation.
    pub fn epoch(&self) -> &LocalScopeEpoch {
        &self.epoch
    }
    /// Held native scope for cross-backend binding checks.
    pub fn local_scope(&self) -> &LocalKernelScope {
        self.epoch.lifecycle.local_scope()
    }
}

/// Verified containment and a held shared barrier for one backend operation.
pub struct LocalContainedOperation {
    epoch: LocalScopeEpoch,
    contained: ContainedScope,
    _barrier: OwnedRwLockReadGuard<()>,
}
impl LocalContainedOperation {
    /// Recheck closure and the local epoch immediately before every effect.
    pub fn recheck(&self) -> Result<(), Error> {
        self.epoch.recheck()?;
        self.contained.recheck()?;
        Ok(())
    }
    /// Retain an opaque reset binding for later stale-receipt checks.
    pub fn epoch(&self) -> LocalScopeEpoch {
        self.epoch.clone()
    }
    /// The held local scope used to bind the namespace actor.
    pub fn local_scope(&self) -> &LocalKernelScope {
        self.contained.scope()
    }
}

/// Read-only owner-process observation with separate foreign-filter diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalScopeInspectionResult {
    state: LocalScopeInspection,
    foreign_filters_present: bool,
}
impl LocalScopeInspectionResult {
    fn new(
        containment: ContainmentInspection,
        owned_empty: bool,
        foreign_filters_present: bool,
    ) -> Self {
        let state = match containment {
            ContainmentInspection::OwnedAndContained => LocalScopeInspection::OwnedAndContained,
            ContainmentInspection::OwnedPartial => LocalScopeInspection::OwnedPartialContainment,
            ContainmentInspection::Absent if owned_empty => LocalScopeInspection::Empty,
            ContainmentInspection::Absent => LocalScopeInspection::Uncontained,
        };
        Self {
            state,
            foreign_filters_present,
        }
    }
    /// Classification of owned containment and registered effects only.
    pub const fn state(self) -> LocalScopeInspection {
        self.state
    }
    /// Preserved filters outside the scope's declared data and containment slots.
    /// This diagnostic never changes [`Self::state`] or grants mutation authority.
    pub const fn foreign_filters_present(self) -> bool {
        self.foreign_filters_present
    }
}

/// Read-only pre-admission classification of the complete declared owned scope.
///
/// No variant is a startup observation or authorizes disruption, rebuild or
/// activation. A nonempty predecessor still needs an authorized contained reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalScopeInspection {
    /// All registered owned effects and owned containment filters are absent.
    /// Preserved foreign filters do not affect this classification.
    Empty,
    /// Owned complete containment covers every hook; predecessor effects may remain.
    OwnedAndContained,
    /// Present bank components are owned, but a bank or covered hook is incomplete.
    /// This is inspectable predecessor state, not a failure requiring retry.
    OwnedPartialContainment,
    /// Owned effects remain without any reserved containment filters.
    Uncontained,
}

/// Which freshly observed local condition accompanies held exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalStartupState {
    /// All registered effects are absent; no containment window was needed.
    ExclusionHeldAndEmpty,
    /// Every declared path has freshly verified containment.
    ExclusionHeldAndContained,
}
/// Nonserializable local observation; remote authentication is a separate step.
pub struct LocalStartupObservation {
    lifecycle: LocalKernelLifecycle,
    state: LocalStartupState,
}
impl LocalStartupObservation {
    /// The observation class, without local identifiers.
    pub fn state(&self) -> LocalStartupState {
        self.state
    }
    /// Guard retained by the observation, never a fresh effect authority.
    pub fn local_scope(&self) -> &LocalKernelScope {
        self.lifecycle.local_scope()
    }
}

struct NativeReset {
    lifecycle: LocalKernelLifecycle,
    participants: LocalResetParticipants,
    inventories: Vec<ArtifactInventory>,
    contained: Option<ContainedScope>,
    retired: Vec<RetiredArtifact>,
    attempt: Option<crate::CleanupAttempt>,
    residue: residue::Residue,
}
impl NativeReset {
    fn check(&self) -> Result<(), Error> {
        if self.attempt.is_some_and(|attempt| !attempt.has_budget()) {
            return Err(Error::Indeterminate);
        }
        self.lifecycle.local_scope().verify().map_err(Into::into)
    }
    fn contained(&self) -> Result<&ContainedScope, Error> {
        self.contained
            .as_ref()
            .ok_or(Error::Incomplete(ResetPhase::Contain))
    }
    async fn routes_empty(&self) -> Result<bool, Error> {
        for scope in &self.lifecycle.inner.routes {
            self.check()?;
            let snapshot = self
                .participants
                .routes
                .snapshot_owned_route_rules(*scope)
                .await
                .map_err(|_| Error::Incomplete(ResetPhase::Routes))?;
            if snapshot.scope() != *scope
                || !snapshot.routes().is_empty()
                || !snapshot.rules().is_empty()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn empty(&self) -> Result<bool, Error> {
        self.check()?;
        self.lifecycle
            .inner
            .layout
            .verify(self.lifecycle.local_scope())?;
        if !self.participants.xfrm.is_empty().await?
            || !self.routes_empty().await?
            || !self.participants.companions.is_empty().await?
        {
            return Ok(false);
        }
        for artifact in &self.lifecycle.inner.artifacts {
            self.check()?;
            if !artifact
                .inspect(self.lifecycle.local_scope())?
                .is_locally_empty()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
#[async_trait]
impl ResetPort for NativeReset {
    fn begin_attempt(&mut self, attempt: crate::CleanupAttempt) {
        self.attempt = Some(attempt);
    }
    fn inspect(&mut self) -> Result<(), Error> {
        self.check()?;
        self.lifecycle.local_scope().verify_containment_owner()?;
        self.lifecycle
            .inner
            .layout
            .verify(self.lifecycle.local_scope())?;
        self.inventories.clear();
        for artifact in &self.lifecycle.inner.artifacts {
            self.check()?;
            let inventory = artifact.inspect(self.lifecycle.local_scope())?;
            same_scope(self.lifecycle.local_scope(), inventory.scope())?;
            if inventory.artifact() != artifact.artifact() {
                return Err(Error::InvalidPlan);
            }
            // Preserve identities even if a later unlink/readback interrupts
            // retirement and the next inventory is already locally empty.
            self.residue.capture(&inventory);
            self.inventories.push(inventory);
        }
        Ok(())
    }
    fn contain(&mut self) -> Result<(), Error> {
        self.check()?;
        self.contained = Some(self.lifecycle.local_scope().contain()?);
        Ok(())
    }
    fn coverage(&self) -> Result<(), Error> {
        self.check()?;
        self.contained()?.recheck()?;
        Ok(())
    }
    async fn xfrm(&mut self) -> Result<(), Error> {
        self.participants
            .xfrm
            .reset_contained(self.contained()?)
            .await?;
        if !self.participants.xfrm.is_empty().await? {
            return Err(Error::Incomplete(ResetPhase::Xfrm));
        }
        Ok(())
    }
    async fn routes(&mut self) -> Result<(), Error> {
        for scope in &self.lifecycle.inner.routes {
            self.coverage()?;
            let desired =
                OwnedRouteRuleSet::new(*scope, vec![], vec![]).map_err(|_| Error::InvalidPlan)?;
            let outcome = self
                .participants
                .routes
                .reconcile_owned_route_rules(desired)
                .await
                .map_err(|_| Error::Incomplete(ResetPhase::Routes))?;
            if outcome.snapshot.scope() != *scope
                || !outcome.snapshot.routes().is_empty()
                || !outcome.snapshot.rules().is_empty()
            {
                return Err(Error::Incomplete(ResetPhase::Routes));
            }
        }
        if !self.routes_empty().await? {
            return Err(Error::Incomplete(ResetPhase::Routes));
        }
        Ok(())
    }
    async fn companions(&mut self) -> Result<(), Error> {
        self.participants
            .companions
            .reset_contained(self.contained()?)
            .await?;
        if !self.participants.companions.is_empty().await? {
            return Err(Error::Incomplete(ResetPhase::Companions));
        }
        Ok(())
    }
    fn artifacts(&mut self) -> Result<(), Error> {
        self.lifecycle
            .inner
            .layout
            .verify(self.lifecycle.local_scope())?;
        // Recheck backend-specific permanent-history guards immediately before
        // tc effects, retaining the original identity-sensitive descriptors.
        for artifact in &self.lifecycle.inner.artifacts {
            self.check()?;
            artifact.inspect(self.lifecycle.local_scope())?;
        }
        let attempt = self.attempt;
        self.retired.extend(retire_artifacts_checked(
            std::mem::take(&mut self.inventories),
            self.contained()?,
            || {
                if attempt.is_some_and(|attempt| !attempt.has_budget()) {
                    Err(opc_linux_gtpu_sys::tc::ScopeError::Inspection)
                } else {
                    Ok(())
                }
            },
        )?);
        Ok(())
    }
    async fn verify(&mut self) -> Result<(), Error> {
        if !self.empty().await? {
            return Err(Error::Incomplete(ResetPhase::Verify));
        }
        for retired in &self.retired {
            retired.local().recheck()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_linux_gtpu_sys::tc::{
        ArtifactMap, ArtifactProgram, ContainmentBank, LocalHookSpec, TcSlot,
    };
    fn spec(with_data: bool) -> LocalScopeSpec {
        let slot = |p, proto| TcSlot::new(2, TcHook::Egress, 0, proto, p, 1).unwrap();
        let hook = LocalHookSpec::new(
            ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
            ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
        )
        .unwrap();
        LocalScopeSpec::new(
            "/sys/fs/bpf/local".into(),
            "/run/local/guard".into(),
            [1; 16],
            vec![hook],
            if with_data { vec![slot(60, 3)] } else { vec![] },
        )
        .unwrap()
    }
    fn artifact() -> ArtifactSpec {
        ArtifactSpec::new(
            "dscp/eth0".into(),
            vec![ArtifactMap {
                name: "config".into(),
                map_type: 2,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
                flags: 0,
                btf_key_type_id: 0,
                btf_value_type_id: 0,
                map_extra: 0,
                pinned: true,
            }],
            vec![ArtifactProgram {
                name: "dscp".into(),
                tags: vec![[1; 8]],
                maps: vec!["config".into()],
            }],
            vec![(TcSlot::new(2, TcHook::Egress, 0, 3, 60, 1).unwrap(), 0)],
        )
        .unwrap()
    }
    #[test]
    fn foreign_filter_diagnostics_never_change_owned_scope_classification() {
        for (containment, owned_empty, expected) in [
            (
                ContainmentInspection::Absent,
                true,
                LocalScopeInspection::Empty,
            ),
            (
                ContainmentInspection::Absent,
                false,
                LocalScopeInspection::Uncontained,
            ),
            (
                ContainmentInspection::OwnedAndContained,
                true,
                LocalScopeInspection::OwnedAndContained,
            ),
            (
                ContainmentInspection::OwnedAndContained,
                false,
                LocalScopeInspection::OwnedAndContained,
            ),
            (
                ContainmentInspection::OwnedPartial,
                true,
                LocalScopeInspection::OwnedPartialContainment,
            ),
            (
                ContainmentInspection::OwnedPartial,
                false,
                LocalScopeInspection::OwnedPartialContainment,
            ),
        ] {
            for foreign in [false, true] {
                let observed = LocalScopeInspectionResult::new(containment, owned_empty, foreign);
                assert_eq!(observed.state(), expected);
                assert_eq!(observed.foreign_filters_present(), foreign);
            }
        }
    }
    #[test]
    fn dscp_disabled_egress_still_requires_declared_coverage() {
        assert!(validate_plan(&spec(false), &[], &[], &[2]).is_ok());
        assert_eq!(
            validate_plan(&spec(false), &[], &[], &[3]),
            Err(Error::InvalidPlan)
        );
        assert_eq!(
            validate_plan(&spec(false), &[], &[], &[]),
            Err(Error::InvalidPlan)
        );
    }
    #[test]
    fn no_backend_can_omit_the_other_backends_declared_slot() {
        let artifact = artifact();
        assert!(validate_plan(&spec(true), &[&artifact], &[], &[2]).is_ok());
        assert_eq!(
            validate_plan(&spec(true), &[], &[], &[2]),
            Err(Error::InvalidPlan)
        );
        assert_eq!(
            validate_plan(&spec(true), &[&artifact, &artifact], &[], &[2]),
            Err(Error::InvalidPlan)
        );
    }
}
