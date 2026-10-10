use super::tests::*;
use super::*;
use async_trait::async_trait;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
struct Delivery {
    stamp: Mutex<ScopeAuthorityStamp>,
    calls: AtomicUsize,
}
#[async_trait]
impl ScopeAuthorityResponseVerifier for Delivery {
    async fn verify_own_current(
        &self,
        _request: &ScopeAuthorityRequest,
        _execution: &ScopeExecution,
    ) -> Result<ScopeAuthorityStamp, ScopeAuthorityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.stamp.lock().unwrap().clone())
    }
}
#[tokio::test]
async fn remote_capability_factory_checks_complete_own_request_and_successor_provenance() {
    let first = admitted();
    let request = super::tests::request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let verifier = Arc::new(Delivery {
        stamp: Mutex::new(first.view.stamp().unwrap().clone()),
        calls: AtomicUsize::new(0),
    });
    let client = ScopeAuthorityRemote::new(scope(), execution(1), verifier.clone()).unwrap();
    let capability = client.admit(&request).await.unwrap();
    assert_eq!(capability.stamp(), first.view.stamp().unwrap());
    assert!(capability.closed_predecessor().is_none());
    let next = successor(&first, 2);
    let second = first.transition(&next).unwrap();
    *verifier.stamp.lock().unwrap() = second.view.stamp().unwrap().clone();
    assert_eq!(
        client.admit(&next).await,
        Err(ScopeAuthorityError::Unauthorized)
    );
    let successor_client =
        ScopeAuthorityRemote::new(scope(), execution(2), verifier.clone()).unwrap();
    let capability = successor_client.admit(&next).await.unwrap();
    assert_eq!(capability.closed_predecessor(), first.view.stamp());
    *verifier.stamp.lock().unwrap() = first.view.stamp().unwrap().clone();
    assert_eq!(
        successor_client.admit(&next).await,
        Err(ScopeAuthorityError::StaleAuthority)
    );
}
#[tokio::test]
async fn malformed_wrong_revision_scope_and_close_never_mint_remote_authority() {
    let first = admitted();
    let mut wrong = first.view.stamp().unwrap().clone();
    wrong.revision += 1;
    let verifier = Arc::new(Delivery {
        stamp: Mutex::new(wrong),
        calls: AtomicUsize::new(0),
    });
    let client = ScopeAuthorityRemote::new(scope(), execution(1), verifier.clone()).unwrap();
    let initial = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    assert_eq!(
        client.admit(&initial).await,
        Err(ScopeAuthorityError::StaleAuthority)
    );
    let mut wrong_scope = first.view.stamp().unwrap().clone();
    wrong_scope.namespace.scope.slot = [99; 32];
    *verifier.stamp.lock().unwrap() = wrong_scope;
    assert_eq!(
        client.admit(&initial).await,
        Err(ScopeAuthorityError::StaleAuthority)
    );
    let closed = close(&first, 3);
    let before = verifier.calls.load(Ordering::SeqCst);
    assert_eq!(
        client.admit(&closed).await,
        Err(ScopeAuthorityError::InvalidRequest)
    );
    assert_eq!(before, verifier.calls.load(Ordering::SeqCst));
}
#[test]
fn bounded_request_codec_preserves_exact_native_bytes_and_rejects_aliases() {
    let value = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let bytes = value.encode_canonical().unwrap();
    assert_eq!(bytes, postcard::to_allocvec(&value).unwrap());
    assert_eq!(
        ScopeAuthorityRequest::decode_canonical(&bytes).unwrap(),
        value
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeAuthorityRequest::decode_canonical(&trailing).is_err());
    assert!(ScopeAuthorityRequest::decode_canonical(&vec![0; 4097]).is_err());
    // Overlong ULEB128 for the identity length is not a second canonical request.
    let marker = value.operation.execution().identity().as_str().as_bytes();
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let mut alias = bytes.clone();
    alias[start - 1] |= 0x80;
    alias.insert(start, 0);
    assert!(ScopeAuthorityRequest::decode_canonical(&alias).is_err());
}

struct ReadBackend {
    state: Mutex<ScopeState>,
    reads: AtomicUsize,
    commits: AtomicUsize,
}
#[async_trait]
impl super::service::ScopeAuthorityBackend for ReadBackend {
    async fn current(&self, _scope: &ScopeId) -> Result<ScopeState, ScopeAuthorityError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.state.lock().unwrap().clone())
    }
    async fn commit(
        &self,
        _command: ScopeAuthorityCommand,
    ) -> Result<ScopeState, ScopeAuthorityError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        Err(ScopeAuthorityError::Unavailable)
    }
}
struct Reader;
#[async_trait]
impl ScopeAuthorityAdmission for Reader {
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        _scope: &ScopeId,
        _execution: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        _digest: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        if authenticated != &identity("observer")
            || !matches!(
                action,
                ScopeAuthorityAction::Read | ScopeAuthorityAction::Recover
            )
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(ScopeAuthorityRole::Observer)
    }
}
#[tokio::test]
async fn exact_authority_outcome_reads_once_and_never_invents_a_not_applied_result() {
    let initial = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let backend = Arc::new(ReadBackend {
        state: Mutex::new(admitted()),
        reads: AtomicUsize::new(0),
        commits: AtomicUsize::new(0),
    });
    let store = ScopeAuthorityStore {
        backend: backend.clone(),
        scope: scope(),
        admission: Arc::new(Reader),
    };
    let exact = store
        .outcome(
            &identity("observer"),
            *initial.request_id(),
            initial.digest().unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(exact, ScopeAuthorityOutcome::Committed(_)));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .outcome(&identity("observer"), *initial.request_id(), [9; 32])
            .await,
        Err(ScopeAuthorityError::IdempotencyConflict)
    );
    let next = successor(&backend.state.lock().unwrap(), 2);
    let advanced = backend.state.lock().unwrap().transition(&next).unwrap();
    *backend.state.lock().unwrap() = advanced;
    assert!(matches!(
        store
            .outcome(
                &identity("observer"),
                *initial.request_id(),
                initial.digest().unwrap()
            )
            .await
            .unwrap(),
        ScopeAuthorityOutcome::ReceiptUnavailable(_)
    ));
    assert_eq!(backend.commits.load(Ordering::SeqCst), 0);
    let reads = backend.reads.load(Ordering::SeqCst);
    assert_eq!(
        store
            .outcome(
                &identity("unauthorized"),
                *initial.request_id(),
                initial.digest().unwrap()
            )
            .await,
        Err(ScopeAuthorityError::Unauthorized)
    );
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        reads,
        "authorize before exposing retained boot facts"
    );
}
