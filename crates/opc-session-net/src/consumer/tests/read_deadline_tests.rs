//! Transport guards and error classification for budget-bearing reads.

use super::*;

struct AuthorityRejectingConsumer {
    rejection: SessionConsumerRejection,
    calls: Arc<AtomicUsize>,
    mutations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl SessionQuorumConsumer for AuthorityRejectingConsumer {
    async fn execute(
        &self,
        _authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if consumer_operation_is_effectful(request.operation()) {
            self.mutations.fetch_add(1, Ordering::SeqCst);
        }
        SessionConsumerResponse::Rejected(self.rejection)
    }

    async fn watch(
        &self,
        _authorization: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

#[tokio::test]
async fn budgeted_get_preserves_legacy_unauthorized_classification() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mutations = Arc::new(AtomicUsize::new(0));
    let voters = prepared_failover_voters(
        "budgeted-get-unauthorized",
        [
            Some(Arc::new(AuthorityRejectingConsumer {
                rejection: SessionConsumerRejection::Unauthorized,
                calls: Arc::clone(&calls),
                mutations: Arc::clone(&mutations),
            })),
            None,
            None,
        ],
    )
    .await;
    let key = grant_boundary_key("prepared-router-cas", 0x81);
    let legacy = voters.router.clients[0].get(key.clone()).await;
    let budgeted = voters.router.clients[0]
        .get_with_budget(key, prepared_failover_budget())
        .await;
    assert!(matches!(legacy, Err(StoreError::BackendUnavailable(_))));
    assert!(matches!(budgeted, Err(StoreError::BackendUnavailable(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    voters.shutdown().await;
}

#[tokio::test]
async fn cas_and_lease_receipt_authority_rejection_is_cached_terminal() {
    for rejection in [
        SessionConsumerRejection::Unauthorized,
        SessionConsumerRejection::ScopeMismatch,
        SessionConsumerRejection::TopologyMismatch,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mutations = Arc::new(AtomicUsize::new(0));
        let services: [Option<Arc<dyn SessionQuorumConsumer>>; 3] = std::array::from_fn(|_| {
            Some(Arc::new(AuthorityRejectingConsumer {
                rejection,
                calls: Arc::clone(&calls),
                mutations: Arc::clone(&mutations),
            }) as Arc<dyn SessionQuorumConsumer>)
        });
        let voters = prepared_failover_voters("receipt-authority-revocation", services).await;
        let budget = prepared_failover_budget();
        let cas = PersistentPreparedCompareAndSetToken {
            router: Arc::clone(&voters.router),
            request: Arc::new(
                unprotected_router_state_test_compare_and_set_request(voters.scope).await,
            ),
            receipt: OnceLock::new(),
            budget,
            state: PreparedRequestState::new(0),
            terminal_receipt: StdMutex::new(None),
        };
        let mut dispatch = cas.state.begin_dispatch().unwrap();
        dispatch.receipt_only();
        drop(dispatch);
        assert_eq!(
            cas.status_once(budget.original_deadline()).await,
            Err(PreparedCompareAndSetStatusError::TopologyAuthorityRevoked)
        );
        let cas_cursor = cas.state.status_cursor.load(Ordering::Acquire);
        assert_eq!(
            cas.status_once(tokio::time::Instant::now() - Duration::from_millis(1))
                .await,
            Err(PreparedCompareAndSetStatusError::TopologyAuthorityRevoked)
        );
        assert_eq!(cas.state.status_cursor.load(Ordering::Acquire), cas_cursor);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let lease = PersistentPreparedLeaseAcquireToken {
            router: Arc::clone(&voters.router),
            request: Arc::new(SessionConsumerRequest::new(
                voters.scope,
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::AcquireLease {
                    key: grant_boundary_key("prepared-router-cas", 0x82),
                    owner: OwnerId::new("receipt-revocation-owner").unwrap(),
                    ttl: Duration::from_secs(30),
                },
            )),
            receipt: OnceLock::new(),
            budget,
            state: PreparedRequestState::new(0),
            terminal_receipt: StdMutex::new(None),
        };
        let mut dispatch = lease.state.begin_dispatch().unwrap();
        dispatch.receipt_only();
        drop(dispatch);
        assert_eq!(
            lease.status_once(budget.original_deadline()).await,
            Err(PreparedLeaseAcquireStatusError::TopologyAuthorityRevoked)
        );
        let lease_cursor = lease.state.status_cursor.load(Ordering::Acquire);
        assert_eq!(
            lease
                .status_once(tokio::time::Instant::now() - Duration::from_millis(1))
                .await,
            Err(PreparedLeaseAcquireStatusError::TopologyAuthorityRevoked)
        );
        assert_eq!(
            lease.state.status_cursor.load(Ordering::Acquire),
            lease_cursor
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(mutations.load(Ordering::SeqCst), 0);
        voters.shutdown().await;
    }
}

#[tokio::test]
async fn split_deadline_v1_transport_rejects_mutation_before_admission() {
    let calls = Arc::new(AtomicUsize::new(0));
    let voters = prepared_failover_voters(
        "split-read-guard",
        [
            Some(Arc::new(CountingRejectingTestConsumer {
                calls: Arc::clone(&calls),
            })),
            None,
            None,
        ],
    )
    .await;
    let request = unprotected_router_state_test_compare_and_set_request(voters.scope).await;
    let result = voters.router.clients[0]
        .execute_classified_with_deadlines(
            &request,
            tokio::time::Instant::now() + Duration::from_secs(3),
            1,
            Some(tokio::time::Instant::now() + Duration::from_millis(250)),
        )
        .await;
    assert!(matches!(
        result,
        Err(super::super::SessionConsumerCallError::BeforeCallWrite(
            SessionConsumerClientError::Protocol
        ))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no effectful call reaches the wire"
    );
    voters.shutdown().await;
}
