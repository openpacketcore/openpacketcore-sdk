//! Fixed, bounded supervision for Openraft linearizable-read checks.
//!
//! The supervisor only schedules and coalesces calls to Openraft's
//! `ensure_linearizable`; it does not implement an alternate read-index,
//! leadership, quorum, or state-machine-apply algorithm.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use openraft::error::{CheckIsLeaderError, RaftError};
use openraft::{LogId, NodeId, Raft, RaftTypeConfig};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};

use crate::DurableOpenraftRuntime;

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

/// The result of one supervised Openraft linearizability check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnsureLinearizableOutcome<NID>
where
    NID: NodeId,
{
    /// Openraft confirmed leadership and local state-machine application
    /// through this read log ID.
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
    use openraft::{CommittedLeaderId, EmptyNode};
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
        EnsureLinearizableOutcome::Ready {
            read_log_id: Some(LogId::new(CommittedLeaderId::new(3, 7), index)),
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
