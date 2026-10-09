use super::service::ScopeAuthorityBackend;
use super::tests::*;
use super::*;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Admission {
    reject_new: AtomicBool,
    verified: AtomicU64,
}
#[async_trait]
impl ScopeAuthorityAdmission for Admission {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        target: &ScopeId,
        claim: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if target != &scope()
            || claim.is_some_and(|e| e != &execution(1) && e != &execution(2) && e != &execution(3))
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if self.reject_new.load(Ordering::SeqCst)
            && matches!(
                action,
                ScopeAuthorityAction::AdmitInitial | ScopeAuthorityAction::SucceedClosed
            )
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if authenticated == &identity("controller") {
            return Ok(ScopeAuthorityRole::ScopeController);
        }
        if authenticated == &identity("observer") {
            return Ok(ScopeAuthorityRole::Observer);
        }
        if (authenticated == &identity("worker-1")
            || authenticated == &identity("worker-2")
            || authenticated == &identity("worker-3"))
            && claim.is_none_or(|e| e.identity() == authenticated)
        {
            return Ok(ScopeAuthorityRole::Worker);
        }
        Err(ScopeAuthorityError::Unauthorized)
    }
    async fn verify_closure(
        &self,
        _: &SessionConsumerIdentity,
        predecessor: &ScopeAuthorityStamp,
        evidence: &ScopeClosureEvidence,
        _: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        self.verified.fetch_add(1, Ordering::SeqCst);
        if predecessor.execution() == &execution(1) && evidence.digest() == &[2; 32] {
            Ok(())
        } else {
            Err(ScopeAuthorityError::ClosureRequired)
        }
    }
}
#[derive(Clone)]
struct Backend {
    state: Arc<Mutex<ScopeState>>,
    commands: Arc<AtomicU64>,
    lost_reply: Arc<AtomicBool>,
    fail_reads: Arc<AtomicBool>,
}
#[async_trait]
impl ScopeAuthorityBackend for Backend {
    async fn current(&self, _: &ScopeId) -> Result<ScopeState, ScopeAuthorityError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(ScopeAuthorityError::Unavailable);
        }
        Ok(self.state.lock().unwrap().clone())
    }
    async fn commit(
        &self,
        command: ScopeAuthorityCommand,
    ) -> Result<ScopeState, ScopeAuthorityError> {
        self.commands.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        let next = state.transition(&command.request)?;
        *state = next.clone();
        if self.lost_reply.swap(false, Ordering::SeqCst) {
            self.fail_reads.store(true, Ordering::SeqCst);
            Err(ScopeAuthorityError::OutcomeUnknown)
        } else {
            Ok(next)
        }
    }
}
fn setup() -> (ScopeAuthorityStore, Backend, Arc<Admission>) {
    let backend = Backend {
        state: Arc::new(Mutex::new(ScopeState::empty(scope()))),
        commands: Arc::default(),
        lost_reply: Arc::default(),
        fail_reads: Arc::default(),
    };
    let admission = Arc::new(Admission::default());
    (
        ScopeAuthorityStore {
            backend: Arc::new(backend.clone()),
            scope: scope(),
            admission: admission.clone(),
        },
        backend,
        admission,
    )
}
fn initial() -> ScopeAuthorityRequest {
    request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    )
}

#[tokio::test]
async fn required_successor_provenance_is_issued_only_for_committed_handoff() {
    let (store, backend, _) = setup();
    let first = store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    assert_eq!(first.closed_predecessor(), None);
    let before = backend.state.lock().unwrap().clone();
    let next = successor(&before, 2);
    store.execute(&identity("controller"), &next).await.unwrap();
    let recovered = store.admit(&identity("worker-2"), &next).await.unwrap();
    assert_eq!(recovered.closed_predecessor(), before.view.stamp());
    assert_eq!(
        recovered.closed_predecessor().unwrap().namespace(),
        recovered.stamp().namespace(),
        "restore provenance is tied to the committed same-cohort predecessor"
    );
    assert_eq!(
        store.admit(&identity("observer"), &next).await,
        Err(ScopeAuthorityError::Unauthorized)
    );
}

#[tokio::test]
async fn role_table_and_exact_boot_are_enforced_before_commit() {
    let (store, backend, _) = setup();
    for who in ["controller", "observer", "worker-2", "stranger"] {
        assert_eq!(
            store.execute(&identity(who), &initial()).await,
            Err(ScopeAuthorityError::Unauthorized)
        );
    }
    assert_eq!(backend.commands.load(Ordering::SeqCst), 0);
    let token = store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    assert!(token.check_execution(&execution(1)).is_ok());
    assert!(token.check_execution(&execution(2)).is_err());
    let before = backend.state.lock().unwrap().clone();
    for who in ["controller", "observer", "worker-2"] {
        assert_eq!(
            store.execute(&identity(who), &close(&before, 2)).await,
            Err(ScopeAuthorityError::Unauthorized)
        );
    }
    assert_eq!(
        backend.state.lock().unwrap().encode().unwrap(),
        before.encode().unwrap()
    );
    assert!(store.current(&identity("observer")).await.is_ok());
}

#[tokio::test]
async fn closure_claims_require_independent_verification_and_exact_digest() {
    let (store, backend, policy) = setup();
    store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    let before = backend.state.lock().unwrap().clone();
    let bad = successor(&before, 3);
    assert_eq!(
        store.execute(&identity("controller"), &bad).await,
        Err(ScopeAuthorityError::ClosureRequired)
    );
    assert_eq!(*backend.state.lock().unwrap(), before);
    let good = successor(&before, 2);
    let view = store.execute(&identity("controller"), &good).await.unwrap();
    assert_eq!(view.stamp().unwrap().execution(), &execution(2));
    assert_eq!(policy.verified.load(Ordering::SeqCst), 2);
    assert_eq!(
        store.admit(&identity("controller"), &good).await,
        Err(ScopeAuthorityError::Unauthorized)
    );
    let recovered = store.admit(&identity("worker-2"), &good).await.unwrap();
    assert_eq!(recovered.stamp(), view.stamp().unwrap());
    assert_eq!(backend.commands.load(Ordering::SeqCst), 2);
    assert_eq!(
        policy.verified.load(Ordering::SeqCst),
        2,
        "exact recovery uses retained verification"
    );
    assert!(store
        .admit(&identity("worker-1"), &initial())
        .await
        .is_err());
}

#[tokio::test]
async fn committed_close_is_verifiable_without_repeating_platform_termination() {
    let (store, backend, policy) = setup();
    store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    let before = backend.state.lock().unwrap().clone();
    let closed = store
        .execute(&identity("worker-1"), &close(&before, 2))
        .await
        .unwrap();
    let next = request(
        2,
        3,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: closed.stamp().unwrap().clone(),
            execution: execution(2),
            evidence: closed.closed_evidence().unwrap(),
        },
    );
    assert!(store.admit(&identity("worker-2"), &next).await.is_ok());
    assert_eq!(policy.verified.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lost_reply_recovers_identical_capability_without_rechecking_new_credential_validity() {
    let (store, backend, policy) = setup();
    backend.lost_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        store.admit(&identity("worker-1"), &initial()).await,
        Err(ScopeAuthorityError::OutcomeUnknown)
    );
    backend.fail_reads.store(false, Ordering::SeqCst);
    policy.reject_new.store(true, Ordering::SeqCst);
    let first = store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    let replay = store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(backend.commands.load(Ordering::SeqCst), 1);
    let before = backend.state.lock().unwrap().clone();
    assert_eq!(
        store
            .execute(&identity("controller"), &successor(&before, 2))
            .await,
        Err(ScopeAuthorityError::Unauthorized)
    );
    assert_eq!(*backend.state.lock().unwrap(), before);
}

#[tokio::test]
async fn changed_replay_bytes_and_cross_scope_requests_are_refused_without_mutation() {
    let (store, backend, _) = setup();
    store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    let before = backend.state.lock().unwrap().encode().unwrap();
    let mut changed = initial();
    changed.expected_revision = 1;
    assert_eq!(
        store.execute(&identity("worker-1"), &changed).await,
        Err(ScopeAuthorityError::IdempotencyConflict)
    );
    let mut foreign = initial();
    foreign.scope.slot = [9; 32];
    assert_eq!(
        store.execute(&identity("worker-1"), &foreign).await,
        Err(ScopeAuthorityError::Unauthorized)
    );
    assert_eq!(backend.state.lock().unwrap().encode().unwrap(), before);
    assert_eq!(backend.commands.load(Ordering::SeqCst), 1);
}

#[derive(Default)]
struct BootBound {
    seen: Mutex<Vec<(ScopeAuthorityAction, bool, bool)>>,
}
#[async_trait]
impl ScopeAuthorityAdmission for BootBound {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        _target: &ScopeId,
        claim: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        digest: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        self.seen
            .lock()
            .unwrap()
            .push((action, claim.is_some(), digest.is_some()));
        // A boot-bound claim is never authorized as a plain read: recovery must
        // ask for Recover so the transport can verify the exact boot proof.
        if claim.is_some() && action == ScopeAuthorityAction::Read {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if authenticated == &identity("worker-1") && claim.is_none_or(|e| e == &execution(1)) {
            return Ok(ScopeAuthorityRole::Worker);
        }
        Err(ScopeAuthorityError::Unauthorized)
    }
}

#[tokio::test]
async fn capability_recovery_asks_for_boot_bound_recover() {
    let backend = Backend {
        state: Arc::new(Mutex::new(ScopeState::empty(scope()))),
        commands: Arc::default(),
        lost_reply: Arc::default(),
        fail_reads: Arc::default(),
    };
    let admission = Arc::new(BootBound::default());
    let store = ScopeAuthorityStore {
        backend: Arc::new(backend),
        scope: scope(),
        admission: admission.clone(),
    };
    let first = store
        .admit(&identity("worker-1"), &initial())
        .await
        .unwrap();
    admission.seen.lock().unwrap().clear();
    let replay = store
        .admit(&identity("worker-1"), &initial())
        .await
        .expect("exact recovery succeeds through boot-bound Recover");
    assert_eq!(first, replay);
    assert!(admission
        .seen
        .lock()
        .unwrap()
        .iter()
        .any(
            |(action, claim, digest)| *action == ScopeAuthorityAction::Recover && *claim && *digest
        ));
}

#[derive(Clone)]
struct ClosesBeforeReread {
    inner: Backend,
    armed: Arc<AtomicBool>,
}
#[async_trait]
impl ScopeAuthorityBackend for ClosesBeforeReread {
    async fn current(&self, scope: &ScopeId) -> Result<ScopeState, ScopeAuthorityError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            // The same boot's Close commits between the admission commit and
            // the capability re-read.
            let mut state = self.inner.state.lock().unwrap();
            let closed = state.transition(&close(&state, 9)).unwrap();
            *state = closed;
        }
        self.inner.current(scope).await
    }
    async fn commit(
        &self,
        command: ScopeAuthorityCommand,
    ) -> Result<ScopeState, ScopeAuthorityError> {
        let result = self.inner.commit(command).await;
        self.armed.store(true, Ordering::SeqCst);
        result
    }
}

#[tokio::test]
async fn capability_is_refused_when_stamp_closes_before_reread() {
    let inner = Backend {
        state: Arc::new(Mutex::new(ScopeState::empty(scope()))),
        commands: Arc::default(),
        lost_reply: Arc::default(),
        fail_reads: Arc::default(),
    };
    let store = ScopeAuthorityStore {
        backend: Arc::new(ClosesBeforeReread {
            inner: inner.clone(),
            armed: Arc::default(),
        }),
        scope: scope(),
        admission: Arc::new(Admission::default()),
    };
    assert_eq!(
        store.admit(&identity("worker-1"), &initial()).await,
        Err(ScopeAuthorityError::StaleAuthority),
        "no capability for a stamp that is no longer current and Active"
    );
    assert!(!inner.state.lock().unwrap().view.is_active());
}
