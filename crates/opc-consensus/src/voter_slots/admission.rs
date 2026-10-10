use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{oneshot, watch, RwLock, Semaphore};
use tokio::time::Instant;

use super::*;
use crate::engine::{PeerResponseFence, Raft, RaftTypeConfig};
use crate::{ConsensusNodeId, DurableOpenraftRuntime};

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

/// Read the store's atomically published table and provisional intent.
///
/// Implementations use the ordinary serialized durable database path; a metrics
/// snapshot, client timeout or detached cache cannot prove intent absence.
#[async_trait]
pub trait VoterSlotStateReader: Send + Sync + std::fmt::Debug {
    /// Read one internally consistent strict-durability publication.
    async fn read_voter_slot_state(&self) -> Result<VoterSlotDurableState, VoterReplacementError>;
}

/// The engine-owned response fence and its surrounding application lease boundary.
#[async_trait]
pub trait VoterResponseFenceEngine: Send + Sync + 'static {
    /// Instance-local exact receipt; only its owning runtime may release it.
    type Receipt: Clone + Send + Sync;
    /// Disable cached application read leases before any engine admission change.
    fn disable_application_leases(&self);
    /// Read membership through the engine's serialized queue, never lagging metrics.
    async fn effective_members(&self) -> Result<BTreeSet<ConsensusNodeId>, VoterReplacementError>;
    /// Acknowledge that obsolete remote results can no longer affect engine state.
    async fn fence(&self, peer: ConsensusNodeId) -> Result<Self::Receipt, VoterReplacementError>;
    /// Release exactly one owned fence; obsolete receipts must fail closed.
    async fn release(&self, receipt: Self::Receipt) -> Result<(), VoterReplacementError>;
    /// Require a fresh engine quorum after excluding the lost member from accounting.
    async fn ensure_surviving_quorum(&self, deadline: Instant)
        -> Result<(), VoterReplacementError>;
    /// Control automatic elections/heartbeats; explicit campaigns remain store-gated too.
    fn enable_voting(&self, enabled: bool);
}

/// Production adapter for the exact pinned engine's serialized remote-result fence.
pub struct RaftVoterResponseFence<C: RaftTypeConfig> {
    raft: Raft<C>,
    invalidate_leases: Arc<dyn Fn() + Send + Sync>,
}
impl<C: RaftTypeConfig> std::fmt::Debug for RaftVoterResponseFence<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaftVoterResponseFence")
            .finish_non_exhaustive()
    }
}
impl<C: RaftTypeConfig> RaftVoterResponseFence<C> {
    /// Bind the engine and every application lease cache before opening admission.
    /// The engine must have been constructed with automatic election disabled.
    pub fn new(raft: Raft<C>, invalidate_leases: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            raft,
            invalidate_leases,
        }
    }
}
#[async_trait]
impl<C> VoterResponseFenceEngine for RaftVoterResponseFence<C>
where
    C: RaftTypeConfig<NodeId = ConsensusNodeId, AsyncRuntime = DurableOpenraftRuntime>,
{
    type Receipt = PeerResponseFence<ConsensusNodeId>;
    fn disable_application_leases(&self) {
        (self.invalidate_leases)();
    }
    async fn effective_members(&self) -> Result<BTreeSet<ConsensusNodeId>, VoterReplacementError> {
        self.raft
            .with_raft_state(|state| {
                state
                    .membership_state
                    .effective()
                    .nodes()
                    .map(|(node, _)| *node)
                    .collect()
            })
            .await
            .map_err(|_| VoterReplacementError::Unavailable)
    }
    async fn fence(&self, peer: ConsensusNodeId) -> Result<Self::Receipt, VoterReplacementError> {
        self.raft
            .fence_peer_responses(peer)
            .await
            .map_err(|_| VoterReplacementError::Unavailable)
    }
    async fn release(&self, receipt: Self::Receipt) -> Result<(), VoterReplacementError> {
        match self.raft.release_peer_response_fence(receipt).await {
            Ok(true) => Ok(()),
            _ => Err(VoterReplacementError::Unavailable),
        }
    }
    async fn ensure_surviving_quorum(
        &self,
        deadline: Instant,
    ) -> Result<(), VoterReplacementError> {
        let barrier = async {
            let cut = self
                .raft
                .ensure_linearizable()
                .await
                .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?;
            if let Some(cut) = cut {
                self.raft
                    .wait(None)
                    .applied_index_at_least(Some(cut.index), "voter replacement inherited prefix")
                    .await
                    .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?;
            }
            Ok(())
        };
        tokio::time::timeout_at(deadline, barrier)
            .await
            .map_err(|_| VoterReplacementError::NoSurvivingQuorum)?
    }
    fn enable_voting(&self, enabled: bool) {
        self.raft.runtime_config().elect(enabled);
        self.raft.runtime_config().heartbeat(enabled);
    }
}

/// The leader additionally proves a fresh surviving quorum before proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterIntentOrigin {
    /// New locally authenticated leader proposal.
    Leader,
    /// Exact incoming intent carried by an authenticated retained leader's append.
    ReplicatedAppend,
}

/// Authenticated request class used to resolve an uncommitted retirement.
/// Terms must come from the decoded request whose sender and payload were proved.
#[derive(Debug, Clone, Copy)]
pub enum VoterPeerRequest {
    /// Votes, transfers, application calls and all outbound response admission.
    Other,
    /// An incoming leader's append, including an empty heartbeat.
    AppendEntries {
        /// Term of the authenticated append's leader vote.
        term: u64,
    },
    /// An incoming leader's snapshot chunk.
    InstallSnapshot {
        /// Term of the authenticated snapshot's leader vote.
        term: u64,
    },
}

struct Attempt {
    request: VoterReplacementRequest,
    closed: bool,
    definitive: bool,
}
struct State {
    durable: VoterSlotDurableState,
    ready: bool,
    gates: BTreeMap<ConsensusNodeId, Arc<RwLock<()>>>,
    closed: BTreeSet<ConsensusNodeId>,
    acknowledged: BTreeSet<ConsensusNodeId>,
    attempt: Option<Attempt>,
}

/// Store-owned admission, cancellation ownership and durable fence reconciliation.
///
/// Incoming callers prove their incarnation first. `run_peer` then keeps an
/// accepted engine call owned through definitive completion even if its caller
/// disappears. `run_intent` closes new calls, drains old ones, invalidates leases,
/// installs the serialized core fence and only then dispatches a Prepare.
/// Storage callbacks notify publication but never wait on this coordinator.
pub struct VoterAdmission<E: VoterResponseFenceEngine> {
    local: ConsensusNodeId,
    reader: Arc<dyn VoterSlotStateReader>,
    engine: OnceLock<Arc<E>>,
    state: Mutex<State>,
    serial: tokio::sync::Mutex<BTreeMap<ConsensusNodeId, E::Receipt>>,
    traffic: VoterTrafficWindow,
    calls: Arc<Semaphore>,
    changed: watch::Sender<u64>,
}
impl<E: VoterResponseFenceEngine> std::fmt::Debug for VoterAdmission<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterAdmission").finish_non_exhaustive()
    }
}

impl<E: VoterResponseFenceEngine> VoterAdmission<E> {
    /// Start with all transport closed, before constructing the election-disabled engine.
    pub async fn new(
        local: ConsensusNodeId,
        reader: Arc<dyn VoterSlotStateReader>,
    ) -> Result<Arc<Self>, VoterReplacementError> {
        let durable = reader.read_voter_slot_state().await?;
        let members = known_members(durable.table());
        if !members.contains(&local) && !durable.table().is_retired(local) {
            return Err(VoterReplacementError::UnauthorizedReplacement);
        }
        let (changed, mut changes) = watch::channel(0);
        let result = Arc::new(Self {
            local,
            reader,
            engine: OnceLock::new(),
            state: Mutex::new(State {
                durable,
                ready: false,
                gates: members
                    .iter()
                    .map(|node| (*node, Arc::new(RwLock::new(()))))
                    .collect(),
                closed: BTreeSet::new(),
                acknowledged: BTreeSet::new(),
                attempt: None,
            }),
            serial: tokio::sync::Mutex::new(BTreeMap::new()),
            traffic: VoterTrafficWindow::new(members),
            calls: Arc::new(Semaphore::new(128)),
            changed,
        });
        let weak = Arc::downgrade(&result);
        tokio::spawn(async move {
            while changes.changed().await.is_ok() {
                let mut retry_delay = Duration::from_millis(100);
                loop {
                    let Some(runtime) = weak.upgrade() else {
                        return;
                    };
                    if runtime.engine.get().is_none() {
                        break;
                    }
                    let settled = runtime.reconcile().await.is_ok();
                    drop(runtime);
                    if settled {
                        break;
                    }
                    // Only unresolved publication/fence failures retry. Healthy
                    // idle runtimes perform no periodic database polling. Bound
                    // retries against permanently closed or failed storage too;
                    // a real publication still wakes reconciliation immediately.
                    tokio::select! {
                        _ = tokio::time::sleep(retry_delay) => {
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                        },
                        change = changes.changed() => {
                            if change.is_err() { return; }
                            retry_delay = Duration::from_millis(100);
                        },
                    }
                }
            }
        });
        Ok(result)
    }

    /// Install every durable fence before opening RPCs and automatic voting.
    pub async fn attach_engine(&self, engine: Arc<E>) -> Result<(), VoterReplacementError> {
        engine.enable_voting(false);
        self.engine
            .set(engine)
            .map_err(|_| VoterReplacementError::InvalidTransition)?;
        self.reconcile().await
    }

    /// Notify after strict durable publication. Safe inside storage callbacks: never waits.
    pub fn notify_durable_changed(&self) {
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Read an admission snapshot for deterministic store checks, never as lease/quorum proof.
    pub fn durable_view(&self) -> Result<VoterSlotDurableState, VoterReplacementError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?
            .durable
            .clone())
    }

    /// Count target-key evidence before later refusal, serialized with intent closure.
    pub fn observe_authenticated(
        &self,
        evidence: &AuthenticatedVoterEvidence,
    ) -> Result<(), VoterReplacementError> {
        let state = self
            .state
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?;
        let binding = evidence.binding();
        let table = state.durable.table();
        let known = table.slots.iter().map(|slot| &slot.member).chain(
            table
                .replacement
                .iter()
                .flat_map(|operation| operation.predecessor.members.iter()),
        );
        if table.cluster_instance != binding.cluster_instance
            || !known.into_iter().any(|member| {
                member.identity == binding.source.identity
                    && member.key_digest == binding.source.key_digest
            })
        {
            return Err(VoterReplacementError::UnauthorizedReplacement);
        }
        self.traffic.observe(evidence);
        Ok(())
    }

    /// Fresh local loss-probe answer. Each counted survivor repeats it before dispatch.
    pub fn check_target_absent(
        &self,
        target: ConsensusNodeId,
    ) -> Result<(), VoterReplacementError> {
        let _state = self
            .state
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?;
        self.traffic.check_absent(target)
    }

    /// Whether explicit campaigning or leadership transfer may run locally.
    pub fn local_voting_admitted(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.ready && local_voting(&state, self.local))
    }

    /// Storage-side assertion that this exact Prepare passed the pre-dispatch core barrier.
    /// It is synchronous and cannot self-deadlock an Openraft storage callback.
    pub fn intent_fence_acknowledged(&self, request: &VoterReplacementRequest) -> bool {
        self.state.lock().is_ok_and(|state| {
            let target = target_of(request);
            state.acknowledged.contains(&target)
                && (state
                    .attempt
                    .as_ref()
                    .is_some_and(|attempt| same_request(&attempt.request, request))
                    || state
                        .durable
                        .intent()
                        .is_some_and(|intent| same_request(&intent.request, request))
                    || state.durable.table().is_retired(target))
        })
    }

    /// Assert the pre-install barrier without awaiting from an engine storage callback.
    pub fn snapshot_fences_acknowledged(
        &self,
        incoming: &VoterSlotTable,
        members: &BTreeSet<ConsensusNodeId>,
    ) -> bool {
        self.state.lock().is_ok_and(|state| {
            members
                .iter()
                .filter(|node| incoming.is_retired(**node))
                .all(|node| {
                    if *node == self.local {
                        state.closed.contains(node)
                    } else {
                        state.acknowledged.contains(node)
                    }
                })
        })
    }

    /// Run a proved peer's engine call under a per-peer gate through definitive completion.
    ///
    /// Proof, envelope, family and candidate-voting checks remain store obligations.
    /// The closure is never invoked while startup or retirement admission is closed.
    pub async fn run_peer<T, F, Fut>(
        self: &Arc<Self>,
        peer: ConsensusNodeId,
        deadline: Instant,
        call: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        self.run_peer_request(peer, VoterPeerRequest::Other, deadline, call)
            .await
    }

    /// Run a proved incoming request, admitting only a higher-term leader's
    /// appends or snapshots through a provisional retirement. The engine's
    /// response fence remains installed until durable resolution of the intent.
    pub async fn run_peer_request<T, F, Fut>(
        self: &Arc<Self>,
        peer: ConsensusNodeId,
        request: VoterPeerRequest,
        deadline: Instant,
        call: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        let permit = tokio::time::timeout_at(deadline, self.calls.clone().acquire_owned())
            .await
            .map_err(|_| VoterReplacementError::Deadline)?
            .map_err(|_| VoterReplacementError::Unavailable)?;
        let gate = {
            let state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            peer_admitted(&state, self.local, peer, request)?;
            // The target was drained before its durable intent was appended.
            // A resolving leader must not hold that drain while installing a
            // snapshot: the snapshot barrier also owns the provisional fence.
            if resolving_leader(&state, peer, request) {
                None
            } else {
                Some(
                    state
                        .gates
                        .get(&peer)
                        .cloned()
                        .ok_or(VoterReplacementError::UnauthorizedReplacement)?,
                )
            }
        };
        let drain = match gate {
            Some(gate) => Some(
                tokio::time::timeout_at(deadline, gate.read_owned())
                    .await
                    .map_err(|_| VoterReplacementError::Deadline)?,
            ),
            None => None,
        };
        {
            let state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            peer_admitted(&state, self.local, peer, request)?;
        }
        if Instant::now() >= deadline {
            return Err(VoterReplacementError::Deadline);
        }
        let (reply, result) = oneshot::channel();
        tokio::spawn(async move {
            let response = call().await;
            drop(drain);
            drop(permit);
            let _ = reply.send(response);
        });
        match tokio::time::timeout_at(deadline, result).await {
            Ok(Ok(result)) => result,
            _ => Err(VoterReplacementError::OutcomeUnknown),
        }
    }

    /// Own a single Prepare attempt independently of its caller's deadline or cancellation.
    pub async fn run_intent<T, F, Fut>(
        self: &Arc<Self>,
        request: VoterReplacementRequest,
        origin: VoterIntentOrigin,
        deadline: Instant,
        dispatch: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        self.run_intent_with_preflight(request, origin, deadline, || async { Ok(()) }, dispatch)
            .await
    }

    /// Reserve a leader attempt before probing target liveness.
    ///
    /// An existing attempt or provisional intent is reported before the probe.
    /// The bounded probe and Prepare remain owned through caller cancellation.
    pub async fn run_leader_intent<T, P, PFut, F, Fut>(
        self: &Arc<Self>,
        request: VoterReplacementRequest,
        deadline: Instant,
        probe: P,
        dispatch: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        P: FnOnce() -> PFut + Send + 'static,
        PFut: Future<Output = Result<(), VoterReplacementError>> + Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        self.run_intent_with_preflight(
            request,
            VoterIntentOrigin::Leader,
            deadline,
            probe,
            dispatch,
        )
        .await
    }

    async fn run_intent_with_preflight<T, P, PFut, F, Fut>(
        self: &Arc<Self>,
        request: VoterReplacementRequest,
        origin: VoterIntentOrigin,
        deadline: Instant,
        preflight: P,
        dispatch: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        P: FnOnce() -> PFut + Send + 'static,
        PFut: Future<Output = Result<(), VoterReplacementError>> + Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        if Instant::now() >= deadline {
            return Err(VoterReplacementError::Deadline);
        }
        request.validate()?;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            if !state.ready {
                return Err(VoterReplacementError::Unavailable);
            }
            if state.attempt.is_some()
                || state.durable.intent().is_some_and(|intent| {
                    origin == VoterIntentOrigin::Leader || !same_request(&intent.request, &request)
                })
            {
                return Err(VoterReplacementError::ReplacementInProgress);
            }
            if target_of(&request) == self.local {
                return Err(VoterReplacementError::TargetStillLive);
            }
            state.attempt = Some(Attempt {
                request: request.clone(),
                closed: false,
                definitive: false,
            });
        }
        let runtime = self.clone();
        let (reply, result) = oneshot::channel();
        // No await between reserving the one attempt and transferring ownership.
        tokio::spawn(async move {
            let prepared = async {
                // Recheck the published log, not just the admission cache. A
                // same-request Prepare can still commit after its caller left.
                if origin == VoterIntentOrigin::Leader
                    && runtime
                        .reader
                        .read_voter_slot_state()
                        .await?
                        .intent()
                        .is_some()
                {
                    return Err(VoterReplacementError::ReplacementInProgress);
                }
                tokio::time::timeout_at(deadline, preflight())
                    .await
                    .map_err(|_| VoterReplacementError::Deadline)??;
                let mut receipts = runtime.serial.lock().await;
                runtime
                    .prepare_intent(&mut receipts, &request, origin, deadline)
                    .await
            }
            .await;
            // Closed flags and the owned attempt retain the fence. Do not hold
            // the coordinator mutex while waiting for Raft: a higher-term
            // leader may need it to install the snapshot that resolves us.
            let response = match prepared {
                Ok(()) => dispatch().await,
                Err(error) => Err(error),
            };
            let mut receipts = runtime.serial.lock().await;
            if let Ok(mut state) = runtime.state.lock() {
                if let Some(attempt) = &mut state.attempt {
                    attempt.definitive = true;
                }
            }
            let reconciled = runtime.reconcile_locked(&mut receipts).await;
            if reconciled.is_err() {
                runtime.notify_durable_changed();
            }
            let _ = reply.send(match reconciled {
                Ok(()) => response,
                Err(error) => Err(error),
            });
        });
        match tokio::time::timeout_at(deadline, result).await {
            Ok(Ok(result)) => result,
            _ => Err(VoterReplacementError::OutcomeUnknown),
        }
    }

    async fn prepare_intent(
        &self,
        receipts: &mut BTreeMap<ConsensusNodeId, E::Receipt>,
        request: &VoterReplacementRequest,
        origin: VoterIntentOrigin,
        deadline: Instant,
    ) -> Result<(), VoterReplacementError> {
        let engine = self
            .engine
            .get()
            .ok_or(VoterReplacementError::Unavailable)?;
        let target = target_of(request);
        let durable = self.reader.read_voter_slot_state().await?;
        if durable
            .intent()
            .is_some_and(|intent| !same_request(&intent.request, request))
        {
            return Err(VoterReplacementError::ReplacementInProgress);
        }
        let already_durable = durable.intent().is_some() || durable.table().is_retired(target);
        let gate = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            state.durable = durable;
            if !already_durable {
                self.traffic.check_absent(target)?;
            }
            let gate = state
                .gates
                .get(&target)
                .cloned()
                .ok_or(VoterReplacementError::UnauthorizedReplacement)?;
            if let Some(attempt) = &mut state.attempt {
                attempt.closed = true;
            }
            state.closed.insert(target);
            gate
        };
        let _drained = tokio::time::timeout_at(deadline, gate.write_owned())
            .await
            .map_err(|_| VoterReplacementError::Deadline)?;
        if let std::collections::btree_map::Entry::Vacant(entry) = receipts.entry(target) {
            engine.disable_application_leases();
            let receipt = engine.fence(target).await?;
            entry.insert(receipt);
            self.state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?
                .acknowledged
                .insert(target);
        }
        if origin == VoterIntentOrigin::Leader {
            engine.ensure_surviving_quorum(deadline).await?;
        }
        {
            let _state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            if !already_durable {
                self.traffic.check_absent(target)?;
            }
            if Instant::now() >= deadline {
                return Err(VoterReplacementError::Deadline);
            }
        }
        // Closed flags exclude ordinary calls after this drain is released.
        Ok(())
    }

    /// Reconcile from serialized durable state and serialized engine membership.
    /// Call outside engine storage callbacks; callbacks use `notify_durable_changed`.
    pub async fn reconcile(&self) -> Result<(), VoterReplacementError> {
        let mut receipts = self.serial.lock().await;
        self.reconcile_locked(&mut receipts).await
    }

    /// Fence a fully verified snapshot's retirement floors before engine installation.
    ///
    /// The store validates the complete artifact and metadata first, and the
    /// dispatch future must await definitive engine completion. Caller loss
    /// cannot release this barrier. Do not hold a peer-call guard for an identity
    /// retired by the incoming table; such a sender cannot supply this snapshot.
    pub async fn run_snapshot<T, F, Fut>(
        self: &Arc<Self>,
        incoming: VoterSlotTable,
        incoming_members: BTreeSet<ConsensusNodeId>,
        deadline: Instant,
        dispatch: F,
    ) -> Result<T, VoterReplacementError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, VoterReplacementError>> + Send + 'static,
    {
        let runtime = self.clone();
        let (reply, result) = oneshot::channel();
        tokio::spawn(async move {
            let mut receipts = runtime.serial.lock().await;
            let response = async {
                if Instant::now() >= deadline {
                    return Err(VoterReplacementError::Deadline);
                }
                let engine = runtime
                    .engine
                    .get()
                    .ok_or(VoterReplacementError::Unavailable)?;
                let current = runtime.reader.read_voter_slot_state().await?;
                incoming
                    .validate_successor_of(current.table())
                    .map_err(|_| VoterReplacementError::InvalidTransition)?;
                let mut effective = engine.effective_members().await?;
                effective.extend(incoming_members);
                let incoming_state = VoterSlotDurableState::new(incoming.clone())
                    .map_err(|_| VoterReplacementError::InvalidTransition)?;
                let fences: BTreeSet<_> = incoming_state
                    .engine_fences(&effective)
                    .union(&current.engine_fences(&effective))
                    .copied()
                    .collect();
                let gates = {
                    let mut state = runtime
                        .state
                        .lock()
                        .map_err(|_| VoterReplacementError::Unavailable)?;
                    let closed: BTreeSet<_> = known_members(current.table())
                        .union(&known_members(&incoming))
                        .copied()
                        .filter(|node| incoming.is_retired(*node))
                        .chain(fences.iter().copied())
                        .collect();
                    state.closed.extend(closed.iter().copied());
                    closed
                        .into_iter()
                        .map(|node| {
                            (
                                node,
                                state
                                    .gates
                                    .entry(node)
                                    .or_insert_with(|| Arc::new(RwLock::new(())))
                                    .clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                engine.disable_application_leases();
                if incoming.is_retired(runtime.local) {
                    engine.enable_voting(false);
                }
                let mut drains = Vec::with_capacity(gates.len());
                for (peer, gate) in gates {
                    drains.push(
                        tokio::time::timeout_at(deadline, gate.write_owned())
                            .await
                            .map_err(|_| VoterReplacementError::Deadline)?,
                    );
                    if peer != runtime.local
                        && fences.contains(&peer)
                        && !receipts.contains_key(&peer)
                    {
                        receipts.insert(peer, engine.fence(peer).await?);
                        runtime
                            .state
                            .lock()
                            .map_err(|_| VoterReplacementError::Unavailable)?
                            .acknowledged
                            .insert(peer);
                    }
                }
                // Closed flags exclude new work; release write guards before the
                // engine call, whose normal replication may involve admitted peers.
                drop(drains);
                dispatch().await
            }
            .await;
            let reconciled = runtime.reconcile_locked(&mut receipts).await;
            if reconciled.is_err() {
                runtime.notify_durable_changed();
            }
            let _ = reply.send(match reconciled {
                Ok(()) => response,
                Err(error) => Err(error),
            });
        });
        match tokio::time::timeout_at(deadline, result).await {
            Ok(Ok(result)) => result,
            _ => Err(VoterReplacementError::OutcomeUnknown),
        }
    }

    async fn reconcile_locked(
        &self,
        receipts: &mut BTreeMap<ConsensusNodeId, E::Receipt>,
    ) -> Result<(), VoterReplacementError> {
        let engine = self
            .engine
            .get()
            .ok_or(VoterReplacementError::Unavailable)?;
        let durable = self.reader.read_voter_slot_state().await?;
        let effective = engine.effective_members().await?;
        let mut needed = durable.engine_fences(&effective);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            state.durable = durable;
            if state
                .attempt
                .as_ref()
                .is_some_and(|attempt| attempt.definitive)
            {
                state.attempt = None;
            }
            if let Some(attempt) = &state.attempt {
                if attempt.closed {
                    needed.insert(target_of(&attempt.request));
                }
            }
            self.traffic
                .retain_members(known_members(state.durable.table()));
            for node in known_members(state.durable.table()).union(&needed) {
                state
                    .gates
                    .entry(*node)
                    .or_insert_with(|| Arc::new(RwLock::new(())));
            }
            state.closed.extend(needed.iter().copied());
        }
        for peer in &needed {
            if *peer == self.local || receipts.contains_key(peer) {
                continue;
            }
            let gate = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?
                .gates[peer]
                .clone();
            let _drained = gate.write_owned().await;
            engine.disable_application_leases();
            receipts.insert(*peer, engine.fence(*peer).await?);
            self.state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?
                .acknowledged
                .insert(*peer);
        }
        let release = receipts
            .keys()
            .filter(|peer| !needed.contains(peer))
            .copied()
            .collect::<Vec<_>>();
        for peer in release {
            engine.disable_application_leases();
            engine.release(receipts[&peer].clone()).await?;
            receipts.remove(&peer);
            self.state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?
                .acknowledged
                .remove(&peer);
        }
        let voting = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| VoterReplacementError::Unavailable)?;
            let members = known_members(state.durable.table());
            // Active calls own their Arc guards independently. Once neither
            // the current transition nor an engine fence needs this identity,
            // the durable retirement floor alone rejects all future calls.
            state
                .gates
                .retain(|peer, _| members.contains(peer) || needed.contains(peer));
            state.closed = needed;
            state.ready = true;
            local_voting(&state, self.local)
        };
        engine.enable_voting(voting);
        Ok(())
    }
}

fn target_of(request: &VoterReplacementRequest) -> ConsensusNodeId {
    VoterSlotIdentity::new(
        request.attestation.slot,
        request.attestation.expected_incarnation,
    )
    .node_id()
}
fn same_request(left: &VoterReplacementRequest, right: &VoterReplacementRequest) -> bool {
    left.attestation.request_id == right.attestation.request_id
        && left.attestation.request_digest == right.attestation.request_digest
}
fn known_members(table: &VoterSlotTable) -> BTreeSet<ConsensusNodeId> {
    table
        .slots
        .iter()
        .map(|slot| slot.member.identity.node_id())
        .chain(table.replacement.iter().flat_map(|operation| {
            operation
                .predecessor
                .members
                .iter()
                .map(|member| member.identity.node_id())
        }))
        .collect()
}
fn local_voting(state: &State, local: ConsensusNodeId) -> bool {
    !state.closed.contains(&local)
        && state.durable.table().slots.iter().any(|slot| {
            slot.member.identity.node_id() == local && slot.phase == VoterSlotPhase::Voting
        })
}
fn peer_admitted(
    state: &State,
    local: ConsensusNodeId,
    peer: ConsensusNodeId,
    request: VoterPeerRequest,
) -> Result<(), VoterReplacementError> {
    if !state.ready {
        return Err(VoterReplacementError::Unavailable);
    }
    if state.durable.table().is_retired(local)
        || state.durable.table().is_retired(peer)
        || state.closed.contains(&local)
        || (state.closed.contains(&peer) && !resolving_leader(state, peer, request))
        || !known_members(state.durable.table()).contains(&peer)
    {
        return Err(VoterReplacementError::UnauthorizedReplacement);
    }
    Ok(())
}

fn resolving_leader(state: &State, peer: ConsensusNodeId, request: VoterPeerRequest) -> bool {
    let term = match request {
        VoterPeerRequest::AppendEntries { term } | VoterPeerRequest::InstallSnapshot { term } => {
            term
        }
        VoterPeerRequest::Other => return false,
    };
    !state.durable.table().is_retired(peer)
        && state.acknowledged.contains(&peer)
        && state
            .durable
            .intent()
            .is_some_and(|intent| intent.target() == peer && term > intent.log_id.term)
}
