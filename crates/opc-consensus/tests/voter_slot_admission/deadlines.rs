use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

#[derive(Debug)]
struct DeadlineReader {
    state: Mutex<VoterSlotDurableState>,
    failure: Mutex<Option<VoterReplacementError>>,
    reads_before_failure: Mutex<Option<usize>>,
    deadlines: Mutex<Vec<Instant>>,
    expired: Notify,
}

impl DeadlineReader {
    fn new() -> Self {
        Self {
            state: Mutex::new(VoterSlotDurableState::new(genesis()).unwrap()),
            failure: Mutex::new(None),
            reads_before_failure: Mutex::new(None),
            deadlines: Mutex::new(Vec::new()),
            expired: Notify::new(),
        }
    }
}

#[async_trait]
impl VoterSlotStateReader for DeadlineReader {
    async fn read_voter_slot_state(
        &self,
        deadline: Instant,
    ) -> Result<VoterSlotDurableState, VoterReplacementError> {
        self.deadlines.lock().unwrap().push(deadline);
        if Instant::now() >= deadline {
            self.expired.notify_one();
            return Err(VoterReplacementError::Deadline);
        }
        if let Some(remaining) = self.reads_before_failure.lock().unwrap().as_mut() {
            if *remaining == 0 {
                return Err(VoterReplacementError::Unavailable);
            }
            *remaining -= 1;
        }
        if let Some(error) = self.failure.lock().unwrap().clone() {
            return Err(error);
        }
        self.read_voter_slot_state_now().await
    }

    async fn read_voter_slot_state_now(
        &self,
    ) -> Result<VoterSlotDurableState, VoterReplacementError> {
        Ok(self.state.lock().unwrap().clone())
    }
}

async fn deadline_runtime() -> (
    Arc<VoterAdmission<FenceEngine>>,
    Arc<DeadlineReader>,
    Arc<FenceEngine>,
) {
    let reader = Arc::new(DeadlineReader::new());
    let engine = Arc::new(FenceEngine::default());
    let admission = VoterAdmission::new(node(1), reader.clone()).await.unwrap();
    admission.attach_engine(engine.clone()).await.unwrap();
    (admission, reader, engine)
}

async fn poll_pending<F: Future>(mut future: Pin<&mut F>) {
    let observed = std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await;
    assert!(observed.is_pending());
}

async fn accepted_write_expires_before_the_caller_polls_again(snapshot: bool) {
    let (admission, reader, engine) = deadline_runtime().await;
    tokio::time::advance(VOTER_RECENT_TRAFFIC_WINDOW).await;
    let wanted = request(3, 1);
    let persisted = wanted.clone();
    let cut = VoterSlotLogId { term: 1, index: 10 };
    let mut incoming = genesis();
    incoming
        .apply_control(&VoterSlotControl::Begin(Box::new(wanted.clone())), cut)
        .unwrap();
    let installed = incoming.clone();
    let (entered, started) = oneshot::channel();
    let (release, finish) = oneshot::channel();
    let database = reader.clone();
    let dispatch = move || async move {
        if snapshot {
            database
                .state
                .lock()
                .unwrap()
                .publish_snapshot(installed, cut)
                .unwrap();
        } else {
            database
                .state
                .lock()
                .unwrap()
                .append_intent(VoterSlotIntent {
                    log_id: cut,
                    request: persisted,
                })
                .unwrap();
        }
        entered.send(()).unwrap();
        finish.await.unwrap();
        Ok(())
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    let call = async {
        if snapshot {
            admission
                .run_snapshot(incoming, (1..=3).map(node).collect(), deadline, dispatch)
                .await
        } else {
            admission
                .run_intent(wanted, VoterIntentOrigin::Leader, deadline, dispatch)
                .await
        }
    };
    tokio::pin!(call);
    poll_pending(call.as_mut()).await;
    started.await.unwrap();
    // Leave the observer unpolled while accepted work finishes after expiry.
    // Its next poll must not receive a queued pre-submission Deadline refusal.
    tokio::time::advance(Duration::from_secs(2)).await;
    release.send(()).unwrap();
    reader.expired.notified().await;
    assert_eq!(call.await, Err(VoterReplacementError::OutcomeUnknown));
    assert!(engine.closed.lock().unwrap().contains(&node(3)));
    assert!(reader
        .deadlines
        .lock()
        .unwrap()
        .iter()
        .all(|observed| *observed == deadline));
}

#[tokio::test(start_paused = true)]
async fn accepted_intent_deadline_is_unknown_when_the_caller_resumes() {
    accepted_write_expires_before_the_caller_polls_again(false).await;
}

#[tokio::test(start_paused = true)]
async fn accepted_snapshot_deadline_is_unknown_when_the_caller_resumes() {
    accepted_write_expires_before_the_caller_polls_again(true).await;
}

#[tokio::test(start_paused = true)]
async fn intent_refusal_survives_a_reconciliation_storage_failure() {
    let (admission, reader, _) = deadline_runtime().await;
    let result = admission
        .run_leader_intent(
            request(3, 1),
            Instant::now() + Duration::from_secs(1),
            move || async move {
                *reader.failure.lock().unwrap() = Some(VoterReplacementError::Unavailable);
                Err(VoterReplacementError::TargetStillLive)
            },
            || async { panic!("a refused preflight cannot dispatch") },
        )
        .await;
    assert_eq!(result, Err::<(), _>(VoterReplacementError::TargetStillLive));
}

#[tokio::test(start_paused = true)]
async fn snapshot_refusal_survives_a_reconciliation_storage_failure() {
    let (admission, reader, _) = deadline_runtime().await;
    *reader.reads_before_failure.lock().unwrap() = Some(1);
    let mut incompatible = genesis();
    incompatible.manifest_digest = [0x88; 32];
    let result = admission
        .run_snapshot(
            incompatible,
            (1..=3).map(node).collect(),
            Instant::now() + Duration::from_secs(1),
            || async { panic!("an incompatible snapshot cannot dispatch") },
        )
        .await;
    assert_eq!(
        result,
        Err::<(), _>(VoterReplacementError::InvalidTransition)
    );
}

#[derive(Debug)]
struct HeldFenceEngine {
    base: FenceEngine,
    pause: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
}

#[async_trait]
impl VoterResponseFenceEngine for HeldFenceEngine {
    type Receipt = ConsensusNodeId;

    fn disable_application_leases(&self) {
        self.base.disable_application_leases();
    }

    async fn effective_members(&self) -> Result<BTreeSet<ConsensusNodeId>, VoterReplacementError> {
        self.base.effective_members().await
    }

    async fn fence(&self, peer: ConsensusNodeId) -> Result<Self::Receipt, VoterReplacementError> {
        let receipt = self.base.fence(peer).await?;
        let pause = self.pause.lock().unwrap().take();
        if let Some((entered, resume)) = pause {
            entered.send(()).unwrap();
            resume.await.unwrap();
        }
        Ok(receipt)
    }

    async fn release(&self, receipt: Self::Receipt) -> Result<(), VoterReplacementError> {
        self.base.release(receipt).await
    }

    async fn ensure_surviving_quorum(
        &self,
        deadline: Instant,
    ) -> Result<(), VoterReplacementError> {
        self.base.ensure_surviving_quorum(deadline).await
    }

    fn enable_voting(&self, enabled: bool) {
        self.base.enable_voting(enabled);
    }
}

#[tokio::test(start_paused = true)]
async fn snapshot_does_not_dispatch_when_fencing_consumes_the_deadline() {
    let reader = Arc::new(DeadlineReader::new());
    let (entered, started) = oneshot::channel();
    let (release, resume) = oneshot::channel();
    let engine = Arc::new(HeldFenceEngine {
        base: FenceEngine::default(),
        pause: Mutex::new(Some((entered, resume))),
    });
    let admission = VoterAdmission::new(node(1), reader.clone()).await.unwrap();
    admission.attach_engine(engine).await.unwrap();
    let mut incoming = genesis();
    incoming
        .apply_control(
            &VoterSlotControl::Begin(Box::new(request(3, 1))),
            VoterSlotLogId { term: 1, index: 10 },
        )
        .unwrap();
    let dispatched = Arc::new(AtomicBool::new(false));
    let observed = dispatched.clone();
    let call = admission.run_snapshot(
        incoming,
        (1..=3).map(node).collect(),
        Instant::now() + Duration::from_secs(1),
        move || async move {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    tokio::pin!(call);
    poll_pending(call.as_mut()).await;
    started.await.unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    release.send(()).unwrap();
    reader.expired.notified().await;
    assert_eq!(call.await, Err(VoterReplacementError::Deadline));
    assert!(!dispatched.load(Ordering::SeqCst));
}
