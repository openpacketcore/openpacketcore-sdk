use super::service::ScopeLeaseBackend;
use super::tests::{at, bounds, execution, identity, request, scope};
use super::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct TestClock(Arc<Mutex<ScopeClockBounds>>);
impl ScopeLeaseClock for TestClock {
    fn bounds(&self) -> Result<ScopeClockBounds, ScopeLeaseError> {
        Ok(*self.0.lock().unwrap())
    }
}

#[derive(Clone)]
struct Backend {
    state: Arc<Mutex<ScopeState>>,
    commands: Arc<AtomicU64>,
    mode: Arc<AtomicU8>,
    fail_reads: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
    completed: Arc<tokio::sync::Notify>,
    late_result: Arc<Mutex<Option<Result<ScopeState, ScopeLeaseError>>>>,
}
impl Backend {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ScopeState::empty(scope()))),
            commands: Arc::new(AtomicU64::new(0)),
            mode: Arc::new(AtomicU8::new(0)),
            fail_reads: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(tokio::sync::Notify::new()),
            proceed: Arc::new(tokio::sync::Notify::new()),
            completed: Arc::new(tokio::sync::Notify::new()),
            late_result: Arc::new(Mutex::new(None)),
        }
    }
    fn apply(&self, command: ScopeLeaseCommand) -> Result<ScopeState, ScopeLeaseError> {
        self.commands.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        let next = state.transition(&command.request, command.bounds)?;
        *state = next.clone();
        Ok(next)
    }
}
#[async_trait]
impl ScopeLeaseBackend for Backend {
    async fn current(&self, _: &ScopeLeaseId) -> Result<ScopeState, ScopeLeaseError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(ScopeLeaseError::Unavailable);
        }
        Ok(self.state.lock().unwrap().clone())
    }
    async fn commit(&self, command: ScopeLeaseCommand) -> Result<ScopeState, ScopeLeaseError> {
        match self.mode.swap(0, Ordering::SeqCst) {
            1 => {
                self.apply(command)?;
                self.fail_reads.store(true, Ordering::SeqCst);
                Err(ScopeLeaseError::OutcomeUnknown)
            }
            2 => {
                let backend = self.clone();
                tokio::spawn(async move {
                    backend.entered.notify_one();
                    backend.proceed.notified().await;
                    let result = backend.apply(command);
                    *backend.late_result.lock().unwrap() = Some(result.clone());
                    backend.completed.notify_one();
                    result
                })
                .await
                .unwrap()
            }
            3 => Err(ScopeLeaseError::Unavailable),
            _ => self.apply(command),
        }
    }
}

struct Admission;

#[async_trait]
impl ScopeLeaseAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        target: &ScopeLeaseId,
        execution_claim: Option<&ScopeExecution>,
        action: ScopeLeaseAction,
    ) -> Result<(), ScopeLeaseError> {
        let admitted = target == &scope()
            && execution_claim.is_none_or(|claim| claim == &execution(1) || claim == &execution(2))
            && match action {
                ScopeLeaseAction::Select => authenticated == &identity("controller"),
                ScopeLeaseAction::Read | ScopeLeaseAction::Mutate => {
                    authenticated == &identity("worker-1") || authenticated == &identity("worker-2")
                }
            };
        admitted.then_some(()).ok_or(ScopeLeaseError::Unauthorized)
    }
}

fn setup() -> (ScopeLeaseStore, Backend, TestClock) {
    let clock = TestClock(Arc::new(Mutex::new(bounds(0))));
    let backend = Backend::new();
    let store = ScopeLeaseStore {
        backend: Arc::new(backend.clone()),
        scope: scope(),
        clock: Arc::new(clock.clone()),
        admission: Arc::new(Admission),
    };
    (store, backend, clock)
}

async fn select_and_acquire(store: &ScopeLeaseStore) -> ScopeLeaseView {
    store
        .execute(
            &identity("controller"),
            &request(
                0,
                1,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            ),
        )
        .await
        .unwrap();
    store
        .execute(
            &identity("worker-1"),
            &request(
                1,
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn unauthorized_identity_execution_or_scope_never_reaches_storage() {
    let (store, backend, _) = setup();
    let select = request(
        0,
        1,
        ScopeLeaseOperation::Select {
            execution: execution(1),
        },
    );
    assert_eq!(
        store.execute(&identity("worker-1"), &select).await,
        Err(ScopeLeaseError::Unauthorized)
    );
    for field in 0..4 {
        let mut forged = execution(1);
        match field {
            0 => forged.workload = [9; 16],
            1 => forged.incarnation = [9; 16],
            2 => forged.process = [9; 16],
            _ => forged.admission_generation = 9,
        }
        assert_eq!(
            store
                .execute(
                    &identity("controller"),
                    &request(0, 2, ScopeLeaseOperation::Select { execution: forged })
                )
                .await,
            Err(ScopeLeaseError::Unauthorized)
        );
    }
    let mut foreign = select;
    foreign.scope.slot = [9; 32];
    assert_eq!(
        store.execute(&identity("controller"), &foreign).await,
        Err(ScopeLeaseError::Unauthorized)
    );
    assert_eq!(backend.state.lock().unwrap().view.revision(), 0);
    assert_eq!(
        store.current(&identity("stranger")).await,
        Err(ScopeLeaseError::Unauthorized)
    );
}

#[tokio::test]
async fn authenticated_worker_cannot_renew_another_execution() {
    let (store, _, clock) = setup();
    let acquired = select_and_acquire(&store).await;
    *clock.0.lock().unwrap() = bounds(1);
    let renew = request(
        2,
        3,
        ScopeLeaseOperation::Renew {
            permit: acquired.permit().unwrap().clone(),
        },
    );
    assert_eq!(
        store.execute(&identity("worker-2"), &renew).await,
        Err(ScopeLeaseError::Unauthorized)
    );
    assert!(store.execute(&identity("worker-1"), &renew).await.is_ok());
}

#[tokio::test]
async fn only_authenticated_committed_grants_mint_gate_evidence() {
    let (store, _, clock) = setup();
    let select = request(
        0,
        1,
        ScopeLeaseOperation::Select {
            execution: execution(1),
        },
    );
    assert_eq!(
        store.grant(&identity("controller"), &select).await,
        Err(ScopeLeaseError::InvalidRequest)
    );
    store
        .execute(&identity("controller"), &select)
        .await
        .unwrap();
    let acquire = request(
        1,
        2,
        ScopeLeaseOperation::Acquire {
            execution: execution(1),
            selection: 1,
        },
    );
    assert_eq!(
        store.grant(&identity("worker-2"), &acquire).await,
        Err(ScopeLeaseError::Unauthorized)
    );
    let original = store.grant(&identity("worker-1"), &acquire).await.unwrap();
    *clock.0.lock().unwrap() = bounds(90);
    let replay = store.grant(&identity("worker-1"), &acquire).await.unwrap();
    assert_eq!(replay, original);
    assert_eq!(replay.revision(), 2);
    assert!(!replay.permit().is_live_at(bounds(90)));
}

#[tokio::test]
async fn racing_controllers_cannot_select_two_successors_at_one_revision() {
    let (store, _, _) = setup();
    let first = request(
        0,
        1,
        ScopeLeaseOperation::Select {
            execution: execution(1),
        },
    );
    let second = request(
        0,
        2,
        ScopeLeaseOperation::Select {
            execution: execution(2),
        },
    );
    let controller = identity("controller");
    let (a, b) = tokio::join!(
        store.execute(&controller, &first),
        store.execute(&controller, &second)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let rejection = a.err().or_else(|| b.err()).unwrap();
    assert!(matches!(rejection, ScopeLeaseError::Conflict));
    assert_eq!(
        store
            .current(&identity("worker-1"))
            .await
            .unwrap()
            .revision(),
        1
    );
}

#[tokio::test]
async fn lost_reply_replay_and_restart_preserve_the_original_absolute_deadline() {
    let (store, backend, clock) = setup();
    let acquired = select_and_acquire(&store).await;
    let original = request(
        1,
        2,
        ScopeLeaseOperation::Acquire {
            execution: execution(1),
            selection: 1,
        },
    );
    *clock.0.lock().unwrap() = bounds(90);
    let reopened = ScopeLeaseStore {
        backend: Arc::new(backend),
        scope: scope(),
        clock: Arc::new(clock),
        admission: Arc::new(Admission),
    };
    let replayed = reopened
        .execute(&identity("worker-1"), &original)
        .await
        .unwrap();
    assert_eq!(replayed, acquired);
    assert_eq!(replayed.permit().unwrap().stop_at(), at(61));
    assert!(!replayed.permit().unwrap().is_live_at(bounds(90)));
}

#[tokio::test]
async fn lease_expiry_does_not_prune_the_scope_selection_or_grant_floor() {
    let (store, backend, clock) = setup();
    let acquired = select_and_acquire(&store).await;
    *clock.0.lock().unwrap() = bounds(1000);
    assert_eq!(backend.state.lock().unwrap().view, acquired);
    let view = store.current(&identity("worker-1")).await.unwrap();
    assert_eq!(view, acquired);
    let resumed = store
        .execute(
            &identity("worker-1"),
            &request(
                2,
                3,
                ScopeLeaseOperation::ResumeSameExecution {
                    permit: acquired.permit().unwrap().clone(),
                },
            ),
        )
        .await
        .unwrap();
    assert_eq!(resumed.grant_floor(), 1);
}

#[tokio::test]
async fn stale_configuration_outcome_remains_retryable_with_the_exact_request() {
    let (store, backend, clock) = setup();
    let grant = select_and_acquire(&store).await;
    *clock.0.lock().unwrap() = bounds(1);
    backend.mode.store(3, Ordering::SeqCst);
    let renewal = request(
        2,
        3,
        ScopeLeaseOperation::Renew {
            permit: grant.permit().unwrap().clone(),
        },
    );
    assert_eq!(
        store.execute(&identity("worker-1"), &renewal).await,
        Err(ScopeLeaseError::OutcomeUnknown)
    );
    assert_eq!(store.current(&identity("worker-1")).await.unwrap(), grant);
    let retried = store
        .execute(&identity("worker-1"), &renewal)
        .await
        .unwrap();
    assert_eq!(retried.revision(), 3);
    assert_eq!(retried.permit().unwrap().stop_at(), at(62));
    assert_eq!(backend.commands.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn uncertain_command_resolves_after_reply_and_readback_loss() {
    let (store, backend, clock) = setup();
    let grant = select_and_acquire(&store).await;
    *clock.0.lock().unwrap() = bounds(1);
    backend.mode.store(1, Ordering::SeqCst);
    let renewal = request(
        2,
        3,
        ScopeLeaseOperation::Renew {
            permit: grant.permit().unwrap().clone(),
        },
    );
    assert_eq!(
        store.execute(&identity("worker-1"), &renewal).await,
        Err(ScopeLeaseError::OutcomeUnknown)
    );
    assert_eq!(backend.commands.load(Ordering::SeqCst), 3);
    backend.fail_reads.store(false, Ordering::SeqCst);
    *clock.0.lock().unwrap() = bounds(50);
    let recovered = store
        .execute(&identity("worker-1"), &renewal)
        .await
        .unwrap();
    assert_eq!(recovered.revision(), 3);
    assert_eq!(recovered.permit().unwrap().stop_at(), at(62));
    assert_eq!(
        backend.commands.load(Ordering::SeqCst),
        3,
        "replay adds no command"
    );
}

#[tokio::test]
async fn canceled_late_command_cannot_overwrite_a_new_selector() {
    let (store, backend, _) = setup();
    backend.mode.store(2, Ordering::SeqCst);
    let first = store.clone();
    let pending = tokio::spawn(async move {
        first
            .execute(
                &identity("controller"),
                &request(
                    0,
                    1,
                    ScopeLeaseOperation::Select {
                        execution: execution(1),
                    },
                ),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), backend.entered.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let successor = store
        .execute(
            &identity("controller"),
            &request(
                0,
                2,
                ScopeLeaseOperation::Select {
                    execution: execution(2),
                },
            ),
        )
        .await
        .unwrap();
    backend.proceed.notify_one();
    tokio::time::timeout(Duration::from_secs(2), backend.completed.notified())
        .await
        .unwrap();
    assert_eq!(
        *backend.late_result.lock().unwrap(),
        Some(Err(ScopeLeaseError::Conflict))
    );
    assert_eq!(
        store.current(&identity("worker-2")).await.unwrap(),
        successor
    );
    assert_eq!(successor.selected(), Some(&execution(2)));
}
