//! Fixed, bounded supervision for Openraft linearizable-read checks.
//!
//! The supervisor only schedules and coalesces calls to Openraft's
//! `ensure_linearizable`; it does not implement an alternate read-index,
//! leadership, quorum, or state-machine-apply algorithm.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openraft::error::{CheckIsLeaderError, RaftError};
use openraft::{LogId, NodeId, Raft, RaftMetrics, RaftTypeConfig, ServerState};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};

use crate::{DurableOpenraftRuntime, DURABLE_CONSENSUS_TIMING_PROFILE, DURABLE_OPENRAFT_PROFILE};

/// Fixed worker count, and therefore maximum in-flight Openraft
/// `ensure_linearizable` call count, for one supervisor.
pub const DURABLE_OPENRAFT_LINEARIZABILITY_WORKER_COUNT: usize = 1;

/// Maximum total callers admitted by one linearizability supervisor.
///
/// This bound includes callers in the active Openraft-check cohort and callers
/// queued for a later check. Callers waiting for a permit remain outside the
/// supervisor until capacity becomes available or their absolute deadline
/// expires.
pub const DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY: usize = 64;

/// Fixed maximum lifetime of an opt-in linearizable-read leader lease.
///
/// The lease is intentionally not operator-tunable. It is the smaller of the
/// fixed heartbeat interval and read-barrier deadline, and the timing profile
/// validation guarantees that it remains below the minimum election timeout.
pub const DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE: Duration = Duration::from_millis(
    if DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis
        < DURABLE_CONSENSUS_TIMING_PROFILE.read_barrier_timeout_millis
    {
        DURABLE_OPENRAFT_PROFILE.heartbeat_interval_millis
    } else {
        DURABLE_CONSENSUS_TIMING_PROFILE.read_barrier_timeout_millis
    },
);

/// Select whether a read barrier may reuse a bounded same-term quorum proof.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinearizableReadLease {
    /// Run a fresh coalesced Openraft quorum round for every barrier cohort.
    #[default]
    Disabled,
    /// Reuse a prior successful quorum round only while the fixed lease and
    /// Openraft's same-term local-leader signals both remain valid.
    Enabled,
}

/// A linearizable local-read admission after the required apply wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearizableReadAdmit<NID>
where
    NID: NodeId,
{
    read_log_id: Option<LogId<NID>>,
    term: u64,
}

impl<NID> LinearizableReadAdmit<NID>
where
    NID: NodeId,
{
    /// Return the committed log ID through which the local read was fenced.
    #[must_use]
    pub fn read_log_id(&self) -> Option<LogId<NID>> {
        self.read_log_id.clone()
    }

    /// Return the Openraft term that admitted the read.
    #[must_use]
    pub const fn term(&self) -> u64 {
        self.term
    }
}

/// A fail-closed rejection from a linearizable-read or leader-open barrier.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LinearizableReadBarrierError<NID>
where
    NID: NodeId,
{
    /// Openraft reports a different leader, optionally with a routing hint.
    #[error("the local node is not the current consensus leader")]
    NotLeader {
        /// Openraft's current-leader hint, when known.
        leader: Option<NID>,
    },
    /// Quorum, admission, apply observation, projection rebuild, or the caller
    /// deadline was unavailable.
    #[error("the linearizable-read barrier is unavailable")]
    Unavailable,
}

/// Opaque failure reported by a consumer-owned read-projection rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the read projection could not be rebuilt")]
pub struct ReadProjectionRebuildError;

/// Consumer-owned projection port used by the leader-open barrier.
///
/// The consumer remains responsible for deriving its projection from its
/// Openraft-owned state machine. The SDK supplies the target and independently
/// observes the reported projection log ID before declaring the leader open.
#[async_trait::async_trait]
pub trait LeaderReadProjection<NID>: Send + Sync
where
    NID: NodeId,
{
    /// Subscribe to the log ID represented by the currently serveable
    /// projection. `None` represents an empty canonical state machine.
    fn subscribe_applied(&self) -> watch::Receiver<Option<LogId<NID>>>;

    /// Rebuild the projection through the supplied canonical applied log ID.
    ///
    /// Implementations must honor `deadline`; the SDK also enforces it around
    /// the complete call and then waits for [`Self::subscribe_applied`].
    async fn rebuild_through(
        &self,
        target: Option<LogId<NID>>,
        deadline: Instant,
    ) -> Result<(), ReadProjectionRebuildError>;
}

/// Successful completion of a newly elected leader's projection-open gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderOpenAdmit<NID>
where
    NID: NodeId,
{
    applied_log_id: Option<LogId<NID>>,
    term: u64,
}

impl<NID> LeaderOpenAdmit<NID>
where
    NID: NodeId,
{
    /// Return the exact Openraft-applied log ID represented by the projection.
    #[must_use]
    pub fn applied_log_id(&self) -> Option<LogId<NID>> {
        self.applied_log_id.clone()
    }

    /// Return the same local-leader term verified around the rebuild.
    #[must_use]
    pub const fn term(&self) -> u64 {
        self.term
    }
}

/// The result of one supervised Openraft linearizability check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnsureLinearizableOutcome<NID>
where
    NID: NodeId,
{
    /// Openraft confirmed leadership and returned this read log ID.
    Ready {
        /// The log ID returned by Openraft for the linearizable read.
        read_log_id: Option<LogId<NID>>,
    },
    /// Openraft rejected the local node as leader; retry through this leader
    /// when the hint is present and still belongs to the admitted topology.
    Retry {
        /// Openraft's current-leader hint, if known.
        leader_hint: Option<NID>,
    },
    /// The check did not reach quorum, stopped, or could not obtain bounded
    /// supervisor admission before the caller's deadline.
    Unavailable,
}

#[derive(Debug, Clone)]
struct LeaderLeaseProof<NID>
where
    NID: NodeId,
{
    term: u64,
    read_log_id: Option<LogId<NID>>,
    expires_at: Instant,
}

struct Request<NID>
where
    NID: NodeId,
{
    reply: oneshot::Sender<EnsureLinearizableOutcome<NID>>,
    _admission: OwnedSemaphorePermit,
}

struct RequestDispatcher<NID>
where
    NID: NodeId,
{
    requests: mpsc::Sender<Request<NID>>,
    admission: Arc<Semaphore>,
}

impl<NID> Clone for RequestDispatcher<NID>
where
    NID: NodeId,
{
    fn clone(&self) -> Self {
        Self {
            requests: self.requests.clone(),
            admission: Arc::clone(&self.admission),
        }
    }
}

type OpenraftLinearizableResult<C> = Result<
    Option<LogId<<C as RaftTypeConfig>::NodeId>>,
    RaftError<
        <C as RaftTypeConfig>::NodeId,
        CheckIsLeaderError<<C as RaftTypeConfig>::NodeId, <C as RaftTypeConfig>::Node>,
    >,
>;

/// One reusable, cancellation-safe supervisor for an Openraft node's
/// `ensure_linearizable` calls.
///
/// Exactly one fixed worker and at most one Openraft check are active for this
/// supervisor. Requests admitted before a check starts form one bounded
/// cohort and share its result. Requests admitted after that cohort snapshot
/// wait for a later check. Dropping a caller after supervisor admission only
/// drops its reply receiver; it cannot cancel the worker-owned Openraft call.
///
/// Dropping every supervisor clone closes the request channel. The worker then
/// exits after any already-admitted bounded cohort, so the task has no owner
/// cycle and no detached unbounded lifetime.
pub struct EnsureLinearizableSupervisor<C>
where
    C: RaftTypeConfig,
{
    dispatcher: RequestDispatcher<C::NodeId>,
    config: PhantomData<fn() -> C>,
}

impl<C> Clone for EnsureLinearizableSupervisor<C>
where
    C: RaftTypeConfig,
{
    fn clone(&self) -> Self {
        Self {
            dispatcher: self.dispatcher.clone(),
            config: PhantomData,
        }
    }
}

impl<C> EnsureLinearizableSupervisor<C>
where
    C: RaftTypeConfig<AsyncRuntime = DurableOpenraftRuntime>,
{
    /// Spawn the one fixed supervisor worker for this Openraft handle.
    ///
    /// This must be called from a Tokio runtime. The supplied Openraft handle
    /// remains the sole authority for read index, leadership, quorum, and
    /// state-machine application.
    #[must_use]
    pub fn new(raft: Raft<C>) -> Self {
        let check = move || {
            let raft = raft.clone();
            async move { map_openraft_result::<C>(raft.ensure_linearizable().await) }
        };
        Self {
            dispatcher: spawn_worker(check, DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY),
            config: PhantomData,
        }
    }

    /// Request a supervised Openraft linearizability check under one absolute
    /// caller deadline.
    ///
    /// The deadline covers bounded supervisor admission and awaiting the
    /// shared result. Once admission succeeds, caller cancellation or deadline
    /// expiry does not cancel the worker-owned check.
    pub async fn ensure_linearizable(
        &self,
        deadline: Instant,
    ) -> EnsureLinearizableOutcome<C::NodeId> {
        request_check(&self.dispatcher, deadline).await
    }
}

/// Product-neutral gate for serving a local snapshot after an Openraft read
/// fence and the corresponding local state-machine apply.
///
/// The caller supplies Openraft's metrics watch for the local node. The gate
/// composes those engine-owned leadership, term, and apply signals with
/// [`EnsureLinearizableSupervisor`]; it does not create a second read-index or
/// leadership authority. Clones share both the supervisor and the optional
/// lease proof.
pub struct LinearizableReadBarrier<C>
where
    C: RaftTypeConfig,
{
    local_node_id: C::NodeId,
    supervisor: EnsureLinearizableSupervisor<C>,
    metrics: watch::Receiver<RaftMetrics<C::NodeId, C::Node>>,
    lease: LinearizableReadLease,
    lease_proof: Arc<Mutex<Option<LeaderLeaseProof<C::NodeId>>>>,
}

impl<C> Clone for LinearizableReadBarrier<C>
where
    C: RaftTypeConfig,
{
    fn clone(&self) -> Self {
        Self {
            local_node_id: self.local_node_id.clone(),
            supervisor: self.supervisor.clone(),
            metrics: self.metrics.clone(),
            lease: self.lease,
            lease_proof: Arc::clone(&self.lease_proof),
        }
    }
}

impl<C> LinearizableReadBarrier<C>
where
    C: RaftTypeConfig<AsyncRuntime = DurableOpenraftRuntime>,
{
    /// Create a barrier over an existing coalesced Openraft supervisor.
    ///
    /// Supplying [`LinearizableReadLease::Disabled`] preserves the full-round
    /// behavior and is the production default. The metrics receiver must
    /// belong to the same local Openraft handle as `supervisor`.
    #[must_use]
    pub fn new(
        local_node_id: C::NodeId,
        supervisor: EnsureLinearizableSupervisor<C>,
        metrics: watch::Receiver<RaftMetrics<C::NodeId, C::Node>>,
        lease: LinearizableReadLease,
    ) -> Self {
        Self {
            local_node_id,
            supervisor,
            metrics,
            lease,
            lease_proof: Arc::new(Mutex::new(None)),
        }
    }

    /// Fence one local read under the caller's absolute deadline.
    ///
    /// A successful result is returned only after the local metrics watch has
    /// reached the Openraft read log index. `Retry` and unavailable outcomes
    /// are mapped to typed, fail-closed errors here rather than in consumers.
    pub async fn admit(
        &self,
        deadline: Instant,
    ) -> Result<LinearizableReadAdmit<C::NodeId>, LinearizableReadBarrierError<C::NodeId>> {
        if Instant::now() >= deadline {
            return Err(LinearizableReadBarrierError::Unavailable);
        }

        if self.lease == LinearizableReadLease::Enabled {
            if let Some(admit) = self.try_lease(deadline).await? {
                return Ok(admit);
            }
        }

        // A successful quorum acknowledgement occurs after this request is
        // dispatched. Starting the lease clock here is conservative even if
        // the worker or this task is descheduled before the result is handled;
        // starting it at result delivery could unsafely extend an old proof.
        let round_requested_at = Instant::now();
        let outcome = self.supervisor.ensure_linearizable(deadline).await;
        match outcome {
            EnsureLinearizableOutcome::Ready { read_log_id } => {
                let metrics = self.metrics.borrow().clone();
                let term = self.local_leader_term(&metrics)?;
                self.remember_lease(term, read_log_id.clone(), round_requested_at);

                if let Some(log_id) = &read_log_id {
                    self.wait_for_applied_index(log_id.index, deadline).await?;
                }

                let metrics = self.metrics.borrow().clone();
                self.require_same_local_leader(&metrics, term)?;
                if Instant::now() >= deadline {
                    return Err(LinearizableReadBarrierError::Unavailable);
                }
                Ok(LinearizableReadAdmit { read_log_id, term })
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => {
                self.forget_lease();
                Err(LinearizableReadBarrierError::NotLeader {
                    leader: leader_hint,
                })
            }
            EnsureLinearizableOutcome::Unavailable => {
                self.forget_lease();
                Err(LinearizableReadBarrierError::Unavailable)
            }
        }
    }

    /// Wait for this node's Openraft state machine to apply a log index.
    ///
    /// This is also used after a read barrier was obtained from a remote
    /// leader: the serving node must apply through the returned read index
    /// before reading its own local state.
    pub async fn wait_for_applied_index(
        &self,
        index: u64,
        deadline: Instant,
    ) -> Result<(), LinearizableReadBarrierError<C::NodeId>> {
        let mut metrics = self.metrics.clone();
        loop {
            let applied = metrics
                .borrow()
                .last_applied
                .as_ref()
                .is_some_and(|applied| applied.index >= index);
            if applied {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(LinearizableReadBarrierError::Unavailable);
            }
            match timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    return Err(LinearizableReadBarrierError::Unavailable);
                }
            }
        }
    }

    /// Fence a newly elected leader and rebuild its consumer-owned read
    /// projection before it may be advertised as serveable.
    ///
    /// The helper first executes this barrier, then repeatedly asks the
    /// projection to rebuild to Openraft's exact applied log ID until both are
    /// equal at one same-term local-leader observation. Continuous apply work
    /// remains bounded by `deadline`.
    pub async fn open_leader<P>(
        &self,
        projection: &P,
        deadline: Instant,
    ) -> Result<LeaderOpenAdmit<C::NodeId>, LinearizableReadBarrierError<C::NodeId>>
    where
        P: LeaderReadProjection<C::NodeId> + ?Sized,
    {
        let barrier = self.admit(deadline).await?;
        let term = barrier.term;
        let mut projection_applied = projection.subscribe_applied();

        loop {
            if Instant::now() >= deadline {
                return Err(LinearizableReadBarrierError::Unavailable);
            }
            let metrics = self.metrics.borrow().clone();
            self.require_same_local_leader(&metrics, term)?;
            let target = later_log_id(&barrier.read_log_id, &metrics.last_applied);

            match timeout_at(
                deadline,
                projection.rebuild_through(target.clone(), deadline),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    return Err(LinearizableReadBarrierError::Unavailable);
                }
            }
            wait_for_projection(&mut projection_applied, target, deadline).await?;

            let metrics = self.metrics.borrow().clone();
            self.require_same_local_leader(&metrics, term)?;
            let canonical = later_log_id(&barrier.read_log_id, &metrics.last_applied);
            let projected = projection_applied.borrow().clone();
            match compare_projection(&projected, &canonical) {
                ProjectionComparison::Exact => {
                    if projection_applied.has_changed().is_err() {
                        return Err(LinearizableReadBarrierError::Unavailable);
                    }
                    return Ok(LeaderOpenAdmit {
                        applied_log_id: canonical,
                        term,
                    });
                }
                ProjectionComparison::Behind => {}
                ProjectionComparison::Invalid => {
                    return Err(LinearizableReadBarrierError::Unavailable);
                }
            }
        }
    }

    async fn try_lease(
        &self,
        deadline: Instant,
    ) -> Result<Option<LinearizableReadAdmit<C::NodeId>>, LinearizableReadBarrierError<C::NodeId>>
    {
        let Some(proof) = self.load_lease() else {
            return Ok(None);
        };
        let metrics = self.metrics.borrow().clone();
        if !self.lease_is_valid(&proof, &metrics) {
            return Ok(None);
        }
        let read_log_id = later_log_id(&proof.read_log_id, &metrics.last_applied);
        if let Some(log_id) = &read_log_id {
            self.wait_for_applied_index(log_id.index, deadline).await?;
        }

        let metrics = self.metrics.borrow().clone();
        if !self.lease_is_valid(&proof, &metrics) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(LinearizableReadBarrierError::Unavailable);
        }
        Ok(Some(LinearizableReadAdmit {
            read_log_id,
            term: proof.term,
        }))
    }

    fn local_leader_term(
        &self,
        metrics: &RaftMetrics<C::NodeId, C::Node>,
    ) -> Result<u64, LinearizableReadBarrierError<C::NodeId>> {
        if self.metrics.has_changed().is_err() || metrics.running_state.is_err() {
            return Err(LinearizableReadBarrierError::Unavailable);
        }
        if metrics.state != ServerState::Leader
            || metrics.current_leader != Some(self.local_node_id.clone())
        {
            return Err(LinearizableReadBarrierError::NotLeader {
                leader: metrics.current_leader.clone(),
            });
        }
        Ok(metrics.current_term)
    }

    fn require_same_local_leader(
        &self,
        metrics: &RaftMetrics<C::NodeId, C::Node>,
        term: u64,
    ) -> Result<(), LinearizableReadBarrierError<C::NodeId>> {
        let current_term = self.local_leader_term(metrics)?;
        if current_term != term {
            return Err(LinearizableReadBarrierError::Unavailable);
        }
        Ok(())
    }

    fn lease_is_valid(
        &self,
        proof: &LeaderLeaseProof<C::NodeId>,
        metrics: &RaftMetrics<C::NodeId, C::Node>,
    ) -> bool {
        if Instant::now() >= proof.expires_at
            || self.require_same_local_leader(metrics, proof.term).is_err()
        {
            return false;
        }
        metrics.millis_since_quorum_ack.is_some_and(|age| {
            u128::from(age) <= DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE.as_millis()
        })
    }

    fn remember_lease(
        &self,
        term: u64,
        read_log_id: Option<LogId<C::NodeId>>,
        round_requested_at: Instant,
    ) {
        if self.lease != LinearizableReadLease::Enabled {
            return;
        }
        let Some(expires_at) =
            round_requested_at.checked_add(DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE)
        else {
            return;
        };
        if let Ok(mut proof) = self.lease_proof.lock() {
            *proof = Some(LeaderLeaseProof {
                term,
                read_log_id,
                expires_at,
            });
        }
    }

    fn load_lease(&self) -> Option<LeaderLeaseProof<C::NodeId>> {
        self.lease_proof.lock().ok().and_then(|proof| proof.clone())
    }

    fn forget_lease(&self) {
        if let Ok(mut proof) = self.lease_proof.lock() {
            *proof = None;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionComparison {
    Exact,
    Behind,
    Invalid,
}

fn later_log_id<NID>(left: &Option<LogId<NID>>, right: &Option<LogId<NID>>) -> Option<LogId<NID>>
where
    NID: NodeId,
{
    match (left, right) {
        (Some(left), Some(right)) if right.index > left.index => Some(right.clone()),
        (Some(left), Some(_)) => Some(left.clone()),
        (Some(left), None) => Some(left.clone()),
        (None, Some(right)) => Some(right.clone()),
        (None, None) => None,
    }
}

fn compare_projection<NID>(
    projected: &Option<LogId<NID>>,
    canonical: &Option<LogId<NID>>,
) -> ProjectionComparison
where
    NID: NodeId,
{
    match (projected, canonical) {
        (None, None) => ProjectionComparison::Exact,
        (Some(projected), Some(canonical)) if projected == canonical => ProjectionComparison::Exact,
        (None, Some(_)) => ProjectionComparison::Behind,
        (Some(projected), Some(canonical)) if projected.index < canonical.index => {
            ProjectionComparison::Behind
        }
        (Some(_), None) | (Some(_), Some(_)) => ProjectionComparison::Invalid,
    }
}

async fn wait_for_projection<NID>(
    projection: &mut watch::Receiver<Option<LogId<NID>>>,
    target: Option<LogId<NID>>,
    deadline: Instant,
) -> Result<(), LinearizableReadBarrierError<NID>>
where
    NID: NodeId,
{
    loop {
        if Instant::now() >= deadline {
            return Err(LinearizableReadBarrierError::Unavailable);
        }
        if projection_reached_target(&projection.borrow(), &target) {
            return Ok(());
        }
        match timeout_at(deadline, projection.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Err(LinearizableReadBarrierError::Unavailable),
        }
    }
}

fn projection_reached_target<NID>(
    projected: &Option<LogId<NID>>,
    target: &Option<LogId<NID>>,
) -> bool
where
    NID: NodeId,
{
    match (projected, target) {
        (None, None) => true,
        (Some(_), None) => true,
        (Some(projected), Some(target)) => projected.index >= target.index,
        (None, Some(_)) => false,
    }
}

fn spawn_worker<NID, Check, CheckFuture>(
    check: Check,
    admission_capacity: usize,
) -> RequestDispatcher<NID>
where
    NID: NodeId,
    Check: FnMut() -> CheckFuture + Send + 'static,
    CheckFuture: Future<Output = EnsureLinearizableOutcome<NID>> + Send + 'static,
{
    debug_assert!(admission_capacity > 0);
    let (requests, receiver) = mpsc::channel(admission_capacity);
    tokio::spawn(run_worker(receiver, check, admission_capacity));
    RequestDispatcher {
        requests,
        admission: Arc::new(Semaphore::new(admission_capacity)),
    }
}

async fn run_worker<NID, Check, CheckFuture>(
    mut requests: mpsc::Receiver<Request<NID>>,
    mut check: Check,
    admission_capacity: usize,
) where
    NID: NodeId,
    Check: FnMut() -> CheckFuture,
    CheckFuture: Future<Output = EnsureLinearizableOutcome<NID>>,
{
    let mut cohort = Vec::with_capacity(admission_capacity);
    loop {
        cohort.clear();

        // `recv_many` is the cohort linearization point: every request already
        // admitted to the bounded channel joins this check, while a request
        // admitted after it returns necessarily waits for the next check.
        if requests.recv_many(&mut cohort, admission_capacity).await == 0 {
            return;
        }

        // The worker awaits the exact Openraft result. A caller deadline only
        // drops that caller's reply receiver; it never releases this cohort or
        // starts a second check while Openraft is still resolving the first.
        let outcome = check().await;
        for request in cohort.drain(..) {
            let _ = request.reply.send(outcome.clone());
        }
    }
}

async fn request_check<NID>(
    dispatcher: &RequestDispatcher<NID>,
    deadline: Instant,
) -> EnsureLinearizableOutcome<NID>
where
    NID: NodeId,
{
    if Instant::now() >= deadline {
        return EnsureLinearizableOutcome::Unavailable;
    }

    let admission =
        match timeout_at(deadline, Arc::clone(&dispatcher.admission).acquire_owned()).await {
            Ok(Ok(admission)) => admission,
            Ok(Err(_)) | Err(_) => return EnsureLinearizableOutcome::Unavailable,
        };

    let (reply, response) = oneshot::channel();
    match timeout_at(
        deadline,
        dispatcher.requests.send(Request {
            reply,
            _admission: admission,
        }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return EnsureLinearizableOutcome::Unavailable,
    }

    match timeout_at(deadline, response).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) | Err(_) => EnsureLinearizableOutcome::Unavailable,
    }
}

fn map_openraft_result<C>(
    result: OpenraftLinearizableResult<C>,
) -> EnsureLinearizableOutcome<C::NodeId>
where
    C: RaftTypeConfig,
{
    match result {
        Ok(read_log_id) => EnsureLinearizableOutcome::Ready { read_log_id },
        Err(error) => match error.forward_to_leader::<C::Node>() {
            Some(forward) => EnsureLinearizableOutcome::Retry {
                leader_hint: forward.leader_id.clone(),
            },
            None => EnsureLinearizableOutcome::Unavailable,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Weak};
    use std::time::Duration;

    use openraft::error::{Fatal, ForwardToLeader, QuorumNotEnough};
    use openraft::{CommittedLeaderId, EmptyNode, RaftMetrics, ServerState, Vote};
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    use super::*;

    const TEST_ADMISSION_CAPACITY: usize = 4;
    const LONG_DEADLINE: Duration = Duration::from_secs(60);

    struct Completion {
        reply: oneshot::Sender<EnsureLinearizableOutcome<u64>>,
    }

    struct Probe {
        active: AtomicUsize,
        maximum_active: AtomicUsize,
        invocations: AtomicUsize,
        started: UnboundedSender<Completion>,
    }

    impl Probe {
        fn new(started: UnboundedSender<Completion>) -> Self {
            Self {
                active: AtomicUsize::new(0),
                maximum_active: AtomicUsize::new(0),
                invocations: AtomicUsize::new(0),
                started,
            }
        }

        async fn check(&self) -> EnsureLinearizableOutcome<u64> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum_active.fetch_max(active, Ordering::SeqCst);
            self.invocations.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveGuard(&self.active);
            let (reply, response) = oneshot::channel();
            if self.started.send(Completion { reply }).is_err() {
                return EnsureLinearizableOutcome::Unavailable;
            }
            response
                .await
                .unwrap_or(EnsureLinearizableOutcome::Unavailable)
        }
    }

    struct ActiveGuard<'a>(&'a AtomicUsize);

    impl Drop for ActiveGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn controlled_worker(
        admission_capacity: usize,
    ) -> (
        RequestDispatcher<u64>,
        UnboundedReceiver<Completion>,
        Arc<Probe>,
    ) {
        let (started, invocations) = mpsc::unbounded_channel();
        let probe = Arc::new(Probe::new(started));
        let worker_probe = Arc::clone(&probe);
        let requests = spawn_worker(
            move || {
                let probe = Arc::clone(&worker_probe);
                async move { probe.check().await }
            },
            admission_capacity,
        );
        (requests, invocations, probe)
    }

    fn spawn_request(
        requests: &RequestDispatcher<u64>,
        deadline: Instant,
    ) -> tokio::task::JoinHandle<EnsureLinearizableOutcome<u64>> {
        let requests = requests.clone();
        tokio::spawn(async move { request_check(&requests, deadline).await })
    }

    fn ready(index: u64) -> EnsureLinearizableOutcome<u64> {
        ready_for(3, 7, index)
    }

    fn ready_for(term: u64, node_id: u64, index: u64) -> EnsureLinearizableOutcome<u64> {
        EnsureLinearizableOutcome::Ready {
            read_log_id: Some(LogId::new(CommittedLeaderId::new(term, node_id), index)),
        }
    }

    fn log_id(term: u64, node_id: u64, index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(term, node_id), index)
    }

    fn leader_metrics(term: u64, last_applied: Option<LogId<u64>>) -> RaftMetrics<u64, EmptyNode> {
        let mut metrics = RaftMetrics::new_initial(7);
        metrics.current_term = term;
        metrics.vote = Vote::new_committed(term, 7);
        metrics.last_log_index = last_applied.as_ref().map(|log_id| log_id.index);
        metrics.last_applied = last_applied;
        metrics.state = ServerState::Leader;
        metrics.current_leader = Some(7);
        metrics.millis_since_quorum_ack = Some(0);
        metrics
    }

    type ControlledBarrier = LinearizableReadBarrier<TestConfig>;
    type ControlledBarrierParts = (
        ControlledBarrier,
        watch::Sender<RaftMetrics<u64, EmptyNode>>,
        UnboundedReceiver<Completion>,
        Arc<Probe>,
    );

    fn controlled_barrier(
        lease: LinearizableReadLease,
        last_applied: Option<LogId<u64>>,
    ) -> ControlledBarrierParts {
        let (dispatcher, invocations, probe) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let supervisor = EnsureLinearizableSupervisor {
            dispatcher,
            config: PhantomData,
        };
        let (metrics_tx, metrics) = watch::channel(leader_metrics(3, last_applied));
        (
            LinearizableReadBarrier::new(7, supervisor, metrics, lease),
            metrics_tx,
            invocations,
            probe,
        )
    }

    struct ControlledProjection {
        applied: watch::Receiver<Option<LogId<u64>>>,
        rebuilds: UnboundedSender<Option<LogId<u64>>>,
    }

    #[async_trait::async_trait]
    impl LeaderReadProjection<u64> for ControlledProjection {
        fn subscribe_applied(&self) -> watch::Receiver<Option<LogId<u64>>> {
            self.applied.clone()
        }

        async fn rebuild_through(
            &self,
            target: Option<LogId<u64>>,
            _deadline: Instant,
        ) -> Result<(), ReadProjectionRebuildError> {
            self.rebuilds
                .send(target)
                .map_err(|_| ReadProjectionRebuildError)
        }
    }

    #[tokio::test]
    async fn one_in_flight_batches_only_the_requests_queued_before_start() {
        assert_eq!(DURABLE_OPENRAFT_LINEARIZABILITY_WORKER_COUNT, 1);
        assert_eq!(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY, 64);
        let (requests, mut invocations, probe) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let deadline = Instant::now() + LONG_DEADLINE;

        let first = spawn_request(&requests, deadline);
        let first_check = invocations.recv().await.expect("first check starts");

        let second = spawn_request(&requests, deadline);
        let third = spawn_request(&requests, deadline);
        tokio::task::yield_now().await;
        assert_eq!(requests.requests.capacity(), TEST_ADMISSION_CAPACITY - 2);
        assert_eq!(requests.admission.available_permits(), 1);
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);

        first_check
            .reply
            .send(ready(10))
            .expect("finish first check");
        let second_check = invocations.recv().await.expect("batched check starts");
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);

        let fourth = spawn_request(&requests, deadline);
        tokio::task::yield_now().await;
        assert!(!fourth.is_finished());
        second_check
            .reply
            .send(ready(11))
            .expect("finish second check");
        let third_check = invocations.recv().await.expect("late check starts");
        assert!(!fourth.is_finished());
        third_check
            .reply
            .send(ready(12))
            .expect("finish late check");

        assert_eq!(first.await.expect("first caller"), ready(10));
        assert_eq!(second.await.expect("second caller"), ready(11));
        assert_eq!(third.await.expect("third caller"), ready(11));
        assert_eq!(fourth.await.expect("fourth caller"), ready(12));
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 3);
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn caller_cancellation_after_admission_does_not_cancel_a_check() {
        let (requests, mut invocations, probe) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let deadline = Instant::now() + LONG_DEADLINE;

        let first = spawn_request(&requests, deadline);
        let first_check = invocations.recv().await.expect("first check starts");
        first.abort();
        assert!(first.await.expect_err("caller is cancelled").is_cancelled());
        first_check
            .reply
            .send(ready(20))
            .expect("worker still owns first check");

        let blocker = spawn_request(&requests, deadline);
        let blocker_check = invocations.recv().await.expect("blocker starts");
        let cancelled_queued = spawn_request(&requests, deadline);
        tokio::task::yield_now().await;
        assert_eq!(requests.requests.capacity(), TEST_ADMISSION_CAPACITY - 1);
        cancelled_queued.abort();
        assert!(cancelled_queued
            .await
            .expect_err("queued caller is cancelled")
            .is_cancelled());
        blocker_check.reply.send(ready(21)).expect("finish blocker");
        let cancelled_check = invocations
            .recv()
            .await
            .expect("admitted cancelled caller still starts its check");
        cancelled_check
            .reply
            .send(ready(22))
            .expect("worker owns cancelled caller's check");

        assert_eq!(blocker.await.expect("blocker caller"), ready(21));
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 3);
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_does_not_cancel_an_admitted_check() {
        let (requests, mut invocations, _) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let caller = spawn_request(&requests, Instant::now() + Duration::from_secs(1));
        let check = invocations.recv().await.expect("check starts");

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            caller.await.expect("deadline result"),
            EnsureLinearizableOutcome::Unavailable
        );
        check
            .reply
            .send(ready(30))
            .expect("caller deadline did not cancel worker check");
    }

    #[tokio::test(start_paused = true)]
    async fn total_admission_bound_includes_active_queued_and_cancelled_callers() {
        const CAPACITY: usize = 2;
        let (requests, mut invocations, _) = controlled_worker(CAPACITY);
        let long_deadline = Instant::now() + LONG_DEADLINE;
        let blocker = spawn_request(&requests, long_deadline);
        let blocker_check = invocations.recv().await.expect("blocker starts");

        let cancelled_queued = spawn_request(&requests, long_deadline);
        tokio::task::yield_now().await;
        assert_eq!(requests.admission.available_permits(), 0);
        assert_eq!(requests.requests.capacity(), CAPACITY - 1);

        cancelled_queued.abort();
        assert!(cancelled_queued
            .await
            .expect_err("queued caller is cancelled")
            .is_cancelled());
        assert_eq!(
            requests.admission.available_permits(),
            0,
            "cancelling an admitted caller must not release its worker-owned permit"
        );

        let rejected = spawn_request(&requests, Instant::now() + Duration::from_millis(100));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            rejected.await.expect("queue deadline result"),
            EnsureLinearizableOutcome::Unavailable
        );

        blocker_check.reply.send(ready(40)).expect("finish blocker");
        let cancelled_check = invocations
            .recv()
            .await
            .expect("cancelled admitted request starts its check");
        assert_eq!(requests.admission.available_permits(), 1);

        let late = spawn_request(&requests, long_deadline);
        tokio::task::yield_now().await;
        assert_eq!(
            requests.admission.available_permits(),
            0,
            "active plus queued requests consume the complete fixed bound"
        );
        cancelled_check
            .reply
            .send(ready(41))
            .expect("finish cancelled caller's exact check");
        let late_check = invocations
            .recv()
            .await
            .expect("post-snapshot caller starts a later check");
        late_check.reply.send(ready(42)).expect("finish late check");

        assert_eq!(blocker.await.expect("blocker caller"), ready(40));
        assert_eq!(late.await.expect("late caller"), ready(42));
    }

    #[tokio::test(start_paused = true)]
    async fn elapsed_watchdog_time_never_releases_the_owned_check() {
        let (requests, mut invocations, probe) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = spawn_request(&requests, deadline);
        let first_check = invocations.recv().await.expect("first check starts");
        let second = spawn_request(&requests, deadline);
        tokio::task::yield_now().await;

        tokio::time::advance(crate::DURABLE_CONSENSUS_OPERATION_TIMEOUT * 2).await;
        assert!(!first.is_finished());
        assert!(!second.is_finished());
        assert!(invocations.try_recv().is_err());
        assert_eq!(probe.active.load(Ordering::SeqCst), 1);

        first_check
            .reply
            .send(ready(50))
            .expect("finish exact first check");
        let second_check = invocations
            .recv()
            .await
            .expect("second check starts only after exact completion");
        second_check
            .reply
            .send(ready(51))
            .expect("finish second check");
        assert_eq!(first.await.expect("first caller"), ready(50));
        assert_eq!(second.await.expect("second caller"), ready(51));
        assert_eq!(probe.maximum_active.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn barrier_waits_for_local_apply_before_admitting_an_acked_write() {
        let (barrier, metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Disabled, Some(log_id(3, 7, 9)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let caller = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        let check = invocations.recv().await.expect("read-index round starts");
        check.reply.send(ready(10)).expect("commit read index");

        tokio::task::yield_now().await;
        assert!(
            !caller.is_finished(),
            "a committed index alone must not admit a stale local snapshot"
        );
        metrics.send_modify(|metrics| {
            metrics.last_log_index = Some(10);
            metrics.last_applied = Some(log_id(3, 7, 10));
        });

        let admitted = caller
            .await
            .expect("barrier caller")
            .expect("local apply admits the read");
        assert_eq!(admitted.read_log_id(), Some(log_id(3, 7, 10)));
        assert_eq!(admitted.term(), 3);
    }

    #[tokio::test]
    async fn enabled_lease_reuses_one_same_term_quorum_proof_without_a_new_round() {
        let (barrier, _metrics, mut invocations, probe) =
            controlled_barrier(LinearizableReadLease::Enabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("first full round")
            .reply
            .send(ready(10))
            .expect("complete first round");
        assert_eq!(
            first.await.expect("first caller").expect("first admit"),
            LinearizableReadAdmit {
                read_log_id: Some(log_id(3, 7, 10)),
                term: 3,
            }
        );

        let leased = barrier.admit(deadline).await.expect("leased admit");
        assert_eq!(leased.read_log_id(), Some(log_id(3, 7, 10)));
        assert!(invocations.try_recv().is_err());
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn lease_expiry_and_term_change_each_fall_back_to_a_full_round() {
        let (barrier, metrics, mut invocations, probe) =
            controlled_barrier(LinearizableReadLease::Enabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("initial round")
            .reply
            .send(ready(10))
            .expect("initial proof");
        first
            .await
            .expect("initial caller")
            .expect("initial barrier");

        tokio::time::advance(DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE).await;
        metrics.send_modify(|metrics| {
            metrics.last_log_index = Some(11);
            metrics.last_applied = Some(log_id(3, 7, 11));
            metrics.millis_since_quorum_ack = Some(0);
        });
        let after_expiry = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("expiry starts a full round")
            .reply
            .send(ready(11))
            .expect("renew proof");
        assert_eq!(
            after_expiry
                .await
                .expect("expiry caller")
                .expect("expiry fallback")
                .read_log_id(),
            Some(log_id(3, 7, 11))
        );

        metrics.send_modify(|metrics| {
            *metrics = leader_metrics(4, Some(log_id(4, 7, 12)));
        });
        let after_term_change = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("term change starts a full round")
            .reply
            .send(ready_for(4, 7, 12))
            .expect("same-node new-term proof");
        assert_eq!(
            after_term_change
                .await
                .expect("term caller")
                .expect("term fallback")
                .term(),
            4
        );
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_round_delivery_never_starts_a_fresh_lease_clock() {
        let (barrier, _metrics, mut invocations, probe) =
            controlled_barrier(LinearizableReadLease::Enabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        let delayed = invocations.recv().await.expect("delayed full round");
        tokio::time::advance(DURABLE_OPENRAFT_LINEARIZABLE_LEADER_LEASE).await;
        delayed
            .reply
            .send(ready(10))
            .expect("deliver delayed proof");
        first
            .await
            .expect("delayed caller")
            .expect("full round remains a valid barrier");

        let second = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("expired-at-delivery proof forces a new round")
            .reply
            .send(ready(10))
            .expect("complete replacement proof");
        second
            .await
            .expect("replacement caller")
            .expect("replacement barrier");
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn deposed_live_leader_never_serves_from_its_old_lease() {
        let (barrier, metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Enabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("initial proof")
            .reply
            .send(ready(10))
            .expect("complete initial proof");
        first
            .await
            .expect("initial caller")
            .expect("initial barrier");

        metrics.send_modify(|metrics| {
            metrics.current_term = 4;
            metrics.vote = Vote::new_committed(4, 9);
            metrics.state = ServerState::Follower;
            metrics.current_leader = Some(9);
            metrics.millis_since_quorum_ack = None;
        });
        let stale_read = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("deposition bypasses old lease")
            .reply
            .send(EnsureLinearizableOutcome::Retry {
                leader_hint: Some(9),
            })
            .expect("report new leader");
        assert_eq!(
            stale_read.await.expect("deposed caller"),
            Err(LinearizableReadBarrierError::NotLeader { leader: Some(9) })
        );
    }

    #[tokio::test]
    async fn closed_openraft_metrics_watch_invalidates_an_existing_lease() {
        let (barrier, metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Enabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        let first = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("initial proof")
            .reply
            .send(ready(10))
            .expect("complete initial proof");
        first
            .await
            .expect("initial caller")
            .expect("initial barrier");
        drop(metrics);

        let stopped = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("closed watch cannot use a lease")
            .reply
            .send(EnsureLinearizableOutcome::Unavailable)
            .expect("stopped Openraft result");
        assert_eq!(
            stopped.await.expect("stopped caller"),
            Err(LinearizableReadBarrierError::Unavailable)
        );
    }

    #[tokio::test]
    async fn disabled_lease_preserves_a_fresh_round_for_every_barrier() {
        let (barrier, _metrics, mut invocations, probe) =
            controlled_barrier(LinearizableReadLease::Disabled, Some(log_id(3, 7, 10)));
        let deadline = Instant::now() + LONG_DEADLINE;
        for _ in 0..2 {
            let caller = tokio::spawn({
                let barrier = barrier.clone();
                async move { barrier.admit(deadline).await }
            });
            invocations
                .recv()
                .await
                .expect("disabled mode full round")
                .reply
                .send(ready(10))
                .expect("complete full round");
            assert_eq!(
                caller
                    .await
                    .expect("disabled caller")
                    .expect("disabled barrier")
                    .read_log_id(),
                Some(log_id(3, 7, 10))
            );
        }
        assert_eq!(probe.invocations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn apply_wait_obeys_the_original_caller_deadline() {
        let (barrier, _metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Disabled, Some(log_id(3, 7, 9)));
        let deadline = Instant::now() + Duration::from_secs(1);
        let caller = tokio::spawn({
            let barrier = barrier.clone();
            async move { barrier.admit(deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("round starts")
            .reply
            .send(ready(10))
            .expect("read index resolves");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            caller.await.expect("deadline caller"),
            Err(LinearizableReadBarrierError::Unavailable)
        );
    }

    #[tokio::test]
    async fn leader_open_waits_for_projection_catchup_before_serving() {
        let (barrier, _metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Disabled, Some(log_id(3, 7, 10)));
        let (projection_tx, projection_rx) = watch::channel(Some(log_id(3, 7, 8)));
        let (rebuilds_tx, mut rebuilds_rx) = mpsc::unbounded_channel();
        let projection = Arc::new(ControlledProjection {
            applied: projection_rx,
            rebuilds: rebuilds_tx,
        });
        let deadline = Instant::now() + LONG_DEADLINE;
        let opening = tokio::spawn({
            let barrier = barrier.clone();
            let projection = Arc::clone(&projection);
            async move { barrier.open_leader(projection.as_ref(), deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("leader-open barrier")
            .reply
            .send(ready(10))
            .expect("complete leader-open barrier");
        assert_eq!(
            rebuilds_rx.recv().await.expect("projection rebuild target"),
            Some(log_id(3, 7, 10))
        );
        tokio::task::yield_now().await;
        assert!(!opening.is_finished());

        projection_tx
            .send(Some(log_id(3, 7, 10)))
            .expect("publish rebuilt projection");
        let opened = opening
            .await
            .expect("leader-open caller")
            .expect("leader opens after projection catchup");
        assert_eq!(opened.applied_log_id(), Some(log_id(3, 7, 10)));
        assert_eq!(opened.term(), 3);
    }

    #[tokio::test]
    async fn leader_open_rejects_deposition_during_projection_rebuild() {
        let (barrier, metrics, mut invocations, _) =
            controlled_barrier(LinearizableReadLease::Disabled, Some(log_id(3, 7, 10)));
        let (projection_tx, projection_rx) = watch::channel(Some(log_id(3, 7, 8)));
        let (rebuilds_tx, mut rebuilds_rx) = mpsc::unbounded_channel();
        let projection = Arc::new(ControlledProjection {
            applied: projection_rx,
            rebuilds: rebuilds_tx,
        });
        let deadline = Instant::now() + LONG_DEADLINE;
        let opening = tokio::spawn({
            let barrier = barrier.clone();
            let projection = Arc::clone(&projection);
            async move { barrier.open_leader(projection.as_ref(), deadline).await }
        });
        invocations
            .recv()
            .await
            .expect("leader-open barrier")
            .reply
            .send(ready(10))
            .expect("complete leader-open barrier");
        rebuilds_rx.recv().await.expect("projection rebuild starts");
        metrics.send_modify(|metrics| {
            metrics.current_term = 4;
            metrics.state = ServerState::Follower;
            metrics.current_leader = Some(9);
        });
        projection_tx
            .send(Some(log_id(3, 7, 10)))
            .expect("projection catches old term");
        assert_eq!(
            opening.await.expect("deposed opening caller"),
            Err(LinearizableReadBarrierError::NotLeader { leader: Some(9) })
        );
    }

    #[tokio::test]
    async fn dropping_all_handles_ends_the_fixed_worker_without_an_owner_cycle() {
        let (requests, invocations, probe) = controlled_worker(TEST_ADMISSION_CAPACITY);
        let weak_probe: Weak<Probe> = Arc::downgrade(&probe);
        drop(probe);
        drop(invocations);
        drop(requests);

        for _ in 0..10 {
            if weak_probe.upgrade().is_none() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(weak_probe.upgrade().is_none(), "worker retained its owner");
    }

    #[test]
    fn openraft_results_map_without_creating_an_alternate_authority() {
        type Error = RaftError<u64, CheckIsLeaderError<u64, EmptyNode>>;

        assert_eq!(
            map_openraft_result::<TestConfig>(Ok(Some(LogId::new(
                CommittedLeaderId::new(2, 3),
                5,
            )))),
            EnsureLinearizableOutcome::Ready {
                read_log_id: Some(LogId::new(CommittedLeaderId::new(2, 3), 5)),
            }
        );

        let retry: Error = RaftError::APIError(CheckIsLeaderError::ForwardToLeader(
            ForwardToLeader::new(9, EmptyNode::new()),
        ));
        assert_eq!(
            map_openraft_result::<TestConfig>(Err(retry)),
            EnsureLinearizableOutcome::Retry {
                leader_hint: Some(9),
            }
        );

        let unavailable: Error =
            RaftError::APIError(CheckIsLeaderError::QuorumNotEnough(QuorumNotEnough {
                cluster: "test".to_owned(),
                got: BTreeSet::new(),
            }));
        assert_eq!(
            map_openraft_result::<TestConfig>(Err(unavailable)),
            EnsureLinearizableOutcome::Unavailable
        );
        assert_eq!(
            map_openraft_result::<TestConfig>(Err(RaftError::Fatal(Fatal::Stopped))),
            EnsureLinearizableOutcome::Unavailable
        );
    }

    openraft::declare_raft_types!(
        TestConfig:
            D = String,
            R = String,
            NodeId = u64,
            Node = EmptyNode,
            SnapshotData = Cursor<Vec<u8>>,
            AsyncRuntime = DurableOpenraftRuntime,
    );
}
