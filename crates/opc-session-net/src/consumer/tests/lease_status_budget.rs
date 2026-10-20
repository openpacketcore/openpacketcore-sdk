//! Ordinary lease receipt recovery uses the original caller deadline.

use super::*;

struct HeldLeaseReceipt {
    expected: SessionConsumerLeaseMutationRequest,
    lease: LeaseGuard,
    mutations: AtomicUsize,
    receipts: AtomicUsize,
    gets: AtomicUsize,
    mutation_entered: Notify,
    receipt_entered: Notify,
    release_mutation: Notify,
    release_receipt: Notify,
}

#[async_trait::async_trait]
impl SessionQuorumConsumer for HeldLeaseReceipt {
    async fn execute(
        &self,
        _authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        match request.operation() {
            SessionConsumerOperation::AcquireLease { key, owner, ttl } => {
                assert_eq!(request.request_id(), self.expected.request_id());
                assert_eq!(
                    self.expected.operation(),
                    &SessionConsumerLeaseMutationOperation::Acquire {
                        key: key.clone(),
                        owner: owner.clone(),
                        ttl: *ttl,
                    }
                );
                self.mutations.fetch_add(1, Ordering::SeqCst);
                self.mutation_entered.notify_one();
                self.release_mutation.notified().await;
                SessionConsumerResponse::AcquireLease(Ok(self.lease.clone()))
            }
            SessionConsumerOperation::LeaseMutationStatus { request: retained } => {
                assert_eq!(request.request_id(), self.expected.request_id());
                assert_eq!(retained.as_ref(), &self.expected);
                self.receipts.fetch_add(1, Ordering::SeqCst);
                self.receipt_entered.notify_one();
                self.release_receipt.notified().await;
                SessionConsumerResponse::LeaseMutationStatus(Ok(self.recorded()))
            }
            SessionConsumerOperation::Get { .. } => {
                self.gets.fetch_add(1, Ordering::SeqCst);
                SessionConsumerResponse::Get(Ok(None))
            }
            _ => panic!("unexpected operation in ordinary lease receipt fixture"),
        }
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

impl HeldLeaseReceipt {
    fn recorded(&self) -> SessionConsumerLeaseMutationStatus {
        SessionConsumerLeaseMutationStatus::Recorded(Box::new(Ok(
            SessionConsumerLeaseMutationResult::Acquire(self.lease.clone()),
        )))
    }
}

async fn held_service() -> Arc<HeldLeaseReceipt> {
    let key = grant_boundary_key("prepared-router-cas", 0x91);
    let owner = OwnerId::new("ordinary-lease-budget").unwrap();
    let ttl = Duration::from_secs(30);
    let lease = FakeSessionBackend::new()
        .acquire(&key, owner.clone(), ttl)
        .await
        .unwrap();
    Arc::new(HeldLeaseReceipt {
        expected: SessionConsumerLeaseMutationRequest::new(
            SessionConsumerRequestId::new(),
            SessionConsumerLeaseMutationOperation::Acquire { key, owner, ttl },
        ),
        lease,
        mutations: AtomicUsize::new(0),
        receipts: AtomicUsize::new(0),
        gets: AtomicUsize::new(0),
        mutation_entered: Notify::new(),
        receipt_entered: Notify::new(),
        release_mutation: Notify::new(),
        release_receipt: Notify::new(),
    })
}

async fn receipt_client(
    service: Arc<dyn SessionQuorumConsumer>,
) -> (
    PersistentSessionConsumerClient,
    super::super::SessionQuorumConsumerServerHandle,
) {
    let (client, server) = receipt_client_for_voter(service, 0).await;
    client.prewarm().await.unwrap();
    (client, server)
}

async fn receipt_client_for_voter(
    service: Arc<dyn SessionQuorumConsumer>,
    expected_voter: usize,
) -> (
    PersistentSessionConsumerClient,
    super::super::SessionQuorumConsumerServerHandle,
) {
    let client_identity = material_spiffe("ordinary-lease-budget-client");
    let identities = [
        material_spiffe("ordinary-lease-budget-a"),
        material_spiffe("ordinary-lease-budget-b"),
        material_spiffe("ordinary-lease-budget-c"),
    ];
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let roster = test_consumer_roster_for(&identities);
    let server_authority = voter_authority_for_identity(&roster, &identities[0]);
    let authority = voter_authority_for_identity(&roster, &identities[expected_voter]);
    let grant = opc_session_store::SessionConsumerAuthorizationGrant::try_new(
        client_identity,
        [SessionConsumerTenantNfScope::new(
            TenantId::new("prepared-router-cas").unwrap(),
            NetworkFunctionKind::smf(),
        )],
    )
    .unwrap();
    let authorizer = SessionConsumerAuthorizer::try_new(
        roster
            .authorization_manifest(server_authority.node_id(), [grant])
            .unwrap(),
    )
    .unwrap();
    let (server, address) = SessionQuorumConsumerServer::new(
        service,
        material.trusted_server_config(identities[0].as_str()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    let stateless = StatelessSessionConsumerClient::new(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        authority,
        material.config(),
    )
    .with_operation_timeout(Duration::from_millis(250))
    .with_pre_request_connection_timeout(Duration::from_millis(100));
    let config = PersistentSessionConsumerConfig::try_new(
        2,
        2,
        Duration::from_millis(100),
        1,
        Duration::from_millis(100),
        1,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .unwrap();
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config).unwrap();
    (client, server)
}

// Keep the runtime runnable so only explicit advance calls move its clock,
// including while real loopback TLS sockets wait for readiness.
fn clock_anchor() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    })
}

fn receipt_budget() -> PreparedCheckpointBudget {
    PreparedCheckpointBudget::new(
        tokio::time::Instant::now() + Duration::from_secs(2),
        Duration::from_millis(250),
    )
    .unwrap()
}

async fn receipt_after_lost_mutation(delay_ms: u64) {
    let service = held_service().await;
    let (client, server) = receipt_client(service.clone()).await;
    tokio::time::pause();
    let anchor = clock_anchor();
    let budget = receipt_budget();
    let mutation_client = client.clone();
    let retained = service.expected.clone();
    let mutation = tokio::spawn(async move {
        let SessionConsumerLeaseMutationOperation::Acquire { key, owner, ttl } =
            retained.operation()
        else {
            panic!("acquire fixture")
        };
        mutation_client
            .acquire_with_id(retained.request_id(), key, owner, *ttl)
            .await
    });
    service.mutation_entered.notified().await;
    tokio::time::advance(Duration::from_millis(249)).await;
    assert!(
        !mutation.is_finished(),
        "mutation retains its 250 ms response cap"
    );
    // Tokio's timer wheel rounds wakeups to milliseconds; cross the unchanged
    // 250 ms cap without relying on the paused clock's sub-millisecond origin.
    tokio::time::advance(Duration::from_millis(2)).await;
    assert!(matches!(
        mutation.await.unwrap(),
        Err(SessionConsumerLeaseMutationError::OutcomeUnknown { .. })
    ));
    service.release_mutation.notify_one();
    let receipt_client = client.clone();
    let retained = service.expected.clone();
    let receipt = tokio::spawn(async move {
        receipt_client
            .lease_mutation_status_with_budget(&retained, budget)
            .await
    });
    service.receipt_entered.notified().await;
    tokio::time::advance(Duration::from_millis(delay_ms)).await;
    service.release_receipt.notify_one();
    assert_eq!(
        receipt.await.unwrap(),
        Ok(service.recorded()),
        "receipt at {delay_ms} ms before the original deadline"
    );
    assert!(tokio::time::Instant::now() < budget.original_deadline());
    assert_eq!(service.mutations.load(Ordering::SeqCst), 1);
    assert_eq!(service.receipts.load(Ordering::SeqCst), 1);
    anchor.abort();
    server.abort_and_wait().await;
}

async fn wall_bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    let watchdog = async {
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            tokio::task::yield_now().await;
        }
        panic!("ordinary lease receipt fixture exceeded its wall-clock guard");
    };
    tokio::select! {
        result = future => result,
        () = watchdog => unreachable!(),
    }
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_success_at_200ms() {
    wall_bounded(receipt_after_lost_mutation(200)).await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_success_at_500ms() {
    wall_bounded(receipt_after_lost_mutation(500)).await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_success_at_700ms() {
    wall_bounded(receipt_after_lost_mutation(700)).await;
}

fn start_receipt(
    client: &PersistentSessionConsumerClient,
    service: &HeldLeaseReceipt,
    budget: PreparedCheckpointBudget,
) -> tokio::task::JoinHandle<Result<SessionConsumerLeaseMutationStatus, StoreError>> {
    let client = client.clone();
    let request = service.expected.clone();
    tokio::spawn(async move {
        client
            .lease_mutation_status_with_budget(&request, budget)
            .await
    })
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_preserves_100ms_prewrite_cap() {
    wall_bounded(async {
        let service = held_service().await;
        let (warm, server) = receipt_client(service.clone()).await;
        let mut stateless = warm.pool.client.clone();
        let entered = Arc::new(Notify::new());
        let resolutions = Arc::new(AtomicUsize::new(0));
        stateless.resolve = {
            let entered = Arc::clone(&entered);
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                let entered = Arc::clone(&entered);
                let resolutions = Arc::clone(&resolutions);
                Box::pin(async move {
                    resolutions.fetch_add(1, Ordering::SeqCst);
                    entered.notify_one();
                    std::future::pending().await
                })
            })
        };
        let client =
            PersistentSessionConsumerClient::try_from_stateless(stateless, warm.pool.config)
                .unwrap();
        tokio::time::pause();
        let anchor = clock_anchor();
        let budget = receipt_budget();
        let started = tokio::time::Instant::now();
        let receipt = start_receipt(&client, &service, budget);
        entered.notified().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!receipt.is_finished());
        tokio::time::advance(Duration::from_millis(2)).await;
        assert!(matches!(
            receipt.await.unwrap(),
            Err(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(started.elapsed(), Duration::from_millis(101));
        assert!(tokio::time::Instant::now() < budget.original_deadline());
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(service.receipts.load(Ordering::SeqCst), 0);
        assert_eq!(service.mutations.load(Ordering::SeqCst), 0);
        anchor.abort();
        server.abort_and_wait().await;
    })
    .await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_shares_v1_v2_reserve_and_leaves_ordinary_lane() {
    wall_bounded(async {
        let service = held_service().await;
        let (client, server) = receipt_client(service.clone()).await;
        tokio::time::pause();
        let anchor = clock_anchor();
        let budget = receipt_budget();
        let receipt = start_receipt(&client, &service, budget);
        service.receipt_entered.notified().await;
        let key = service.lease.key().clone();
        let blocked_get = client.get_with_budget(key.clone(), budget);
        let blocked_history = client.fenced_transition_v2_history_state_with_budget(budget);
        tokio::pin!(blocked_get, blocked_history);
        assert!(futures_util::poll!(&mut blocked_get).is_pending());
        assert!(futures_util::poll!(&mut blocked_history).is_pending());
        assert_eq!(
            client.get(key).await,
            Ok(None),
            "ordinary calls retain the second lane"
        );
        tokio::time::advance(Duration::from_millis(101)).await;
        assert!(matches!(
            blocked_get.await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            blocked_history.await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(
            service.gets.load(Ordering::SeqCst),
            1,
            "the extended GET was never transmitted"
        );
        assert_eq!(client.v2_diagnostics().setup_attempts, 0);
        tokio::time::advance(Duration::from_millis(399)).await;
        assert!(
            !receipt.is_finished(),
            "receipt response outlives the mutation cap"
        );
        service.release_receipt.notify_one();
        assert_eq!(receipt.await.unwrap(), Ok(service.recorded()));
        assert_eq!(service.receipts.load(Ordering::SeqCst), 1);
        assert_eq!(service.mutations.load(Ordering::SeqCst), 0);
        anchor.abort();
        server.abort_and_wait().await;
    })
    .await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_transport_loss_spends_deadline_before_retry() {
    wall_bounded(async {
        let service = held_service().await;
        let (client, server) = receipt_client(service.clone()).await;
        tokio::time::pause();
        let anchor = clock_anchor();
        let budget = receipt_budget();
        let request = service.expected.clone();
        let receipt = tokio::spawn(async move {
            let first = client
                .lease_mutation_status_with_budget(&request, budget)
                .await;
            // Model a caller trying another observation with the same budget.
            let retry = client
                .lease_mutation_status_with_budget(&request, budget)
                .await;
            (first, retry)
        });
        service.receipt_entered.notified().await;
        server.abort_and_wait().await;
        tokio::time::advance(Duration::from_millis(1999)).await;
        assert!(
            !receipt.is_finished(),
            "a possibly running read spends the original deadline"
        );
        assert_eq!(service.receipts.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(2)).await;
        let (first, retry) = receipt.await.unwrap();
        assert!(matches!(first, Err(StoreError::BackendUnavailable(_))));
        assert!(matches!(retry, Err(StoreError::BackendUnavailable(_))));
        assert!(tokio::time::Instant::now() >= budget.original_deadline());
        assert_eq!(service.receipts.load(Ordering::SeqCst), 1);
        assert_eq!(service.mutations.load(Ordering::SeqCst), 0);
        anchor.abort();
    })
    .await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_rejects_success_at_or_after_original_deadline() {
    wall_bounded(async {
        for after_deadline_ms in [0, 1] {
            let service = held_service().await;
            let (client, server) = receipt_client(service.clone()).await;
            tokio::time::pause();
            let anchor = clock_anchor();
            let budget = receipt_budget();
            let receipt = start_receipt(&client, &service, budget);
            service.receipt_entered.notified().await;
            tokio::time::advance(Duration::from_millis(2000 + after_deadline_ms)).await;
            assert_eq!(
                tokio::time::Instant::now(),
                budget.original_deadline() + Duration::from_millis(after_deadline_ms)
            );
            service.release_receipt.notify_one();
            // The next advance moves the clock before yielding, so the reply
            // is handled at D + 1 ms (or D + 2 ms), not exactly D. The direct
            // result-mapping test covers equality at the original deadline.
            tokio::time::advance(Duration::from_millis(1)).await;
            assert!(matches!(
                receipt.await.unwrap(),
                Err(StoreError::BackendUnavailable(_))
            ));
            assert!(tokio::time::Instant::now() >= budget.original_deadline());
            assert_eq!(service.receipts.load(Ordering::SeqCst), 1);
            assert_eq!(service.mutations.load(Ordering::SeqCst), 0);
            anchor.abort();
            server.abort_and_wait().await;
            tokio::time::resume();
        }
    })
    .await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_identity_mismatch_is_terminal() {
    wall_bounded(async {
        let service = held_service().await;
        // The trusted server presents voter A's identity; this client expects
        // voter B from the same roster. No Call may reach the receipt service.
        // Use independent pools so the legacy failure's reconnect cooldown
        // cannot delay the budgeted method's first authority observation.
        let (legacy_client, legacy_server) = receipt_client_for_voter(service.clone(), 1).await;
        let (client, server) = receipt_client_for_voter(service.clone(), 1).await;
        tokio::time::pause();
        let anchor = clock_anchor();
        let budget = receipt_budget();
        assert!(matches!(
            legacy_client.lease_mutation_status(&service.expected).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(
            client
                .lease_mutation_status_with_budget(&service.expected, budget)
                .await,
            Err(StoreError::TopologyAuthorityRevoked)
        );
        assert!(tokio::time::Instant::now() < budget.original_deadline());
        assert_eq!(service.receipts.load(Ordering::SeqCst), 0);
        assert_eq!(service.mutations.load(Ordering::SeqCst), 0);
        anchor.abort();
        legacy_server.abort_and_wait().await;
        server.abort_and_wait().await;
    })
    .await;
}

struct FixedLeaseReceipt {
    expected: SessionConsumerLeaseMutationRequest,
    response: SessionConsumerResponse,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl SessionQuorumConsumer for FixedLeaseReceipt {
    async fn execute(
        &self,
        _authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let SessionConsumerOperation::LeaseMutationStatus { request: retained } =
            request.operation()
        else {
            panic!("receipt lookup must not replay any lease mutation");
        };
        assert_eq!(request.request_id(), self.expected.request_id());
        assert_eq!(retained.as_ref(), &self.expected);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.response.clone()
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
async fn ordinary_lease_receipt_budget_preserves_ordinary_error_mapping() {
    wall_bounded(async {
        let fixture = held_service().await;
        let mut responses = [
            SessionConsumerRejection::Unauthorized,
            SessionConsumerRejection::ScopeMismatch,
            SessionConsumerRejection::TopologyMismatch,
            SessionConsumerRejection::MalformedRequest,
            SessionConsumerRejection::Unavailable,
        ]
        .into_iter()
        .map(|rejection| {
            (
                SessionConsumerResponse::Rejected(rejection),
                super::super::rejection_into_store_error(rejection),
            )
        })
        .collect::<Vec<_>>();
        responses.extend(
            [
                SessionConsumerStoreError::Unavailable,
                SessionConsumerStoreError::InvalidInput,
                SessionConsumerStoreError::ProtectedDataRejected,
            ]
            .into_iter()
            .map(|error| {
                (
                    SessionConsumerResponse::LeaseMutationStatus(Err(error)),
                    error.into_store_error(),
                )
            }),
        );
        for (response, expected) in responses {
            let service = Arc::new(FixedLeaseReceipt {
                expected: fixture.expected.clone(),
                response,
                calls: AtomicUsize::new(0),
            });
            let (client, server) = receipt_client(service.clone()).await;
            let budget = receipt_budget();
            assert_eq!(
                client.lease_mutation_status(&service.expected).await,
                Err(expected.clone())
            );
            assert_eq!(
                client
                    .lease_mutation_status_with_budget(&service.expected, budget)
                    .await,
                Err(expected)
            );
            assert!(
                tokio::time::Instant::now() < budget.original_deadline(),
                "complete rejections and revocation do not spend the response budget"
            );
            assert_eq!(service.calls.load(Ordering::SeqCst), 2);
            server.abort_and_wait().await;
        }
    })
    .await;
}

#[tokio::test]
async fn ordinary_lease_receipt_budget_keeps_exact_acquire_renew_release_identity() {
    wall_bounded(async {
        let fixture = held_service().await;
        for operation in [
            fixture.expected.operation().clone(),
            SessionConsumerLeaseMutationOperation::Renew {
                lease: fixture.lease.clone(),
                ttl: Duration::from_secs(20),
            },
            SessionConsumerLeaseMutationOperation::Release {
                lease: fixture.lease.clone(),
            },
        ] {
            let service = Arc::new(FixedLeaseReceipt {
                expected: SessionConsumerLeaseMutationRequest::new(
                    SessionConsumerRequestId::new(),
                    operation,
                ),
                response: SessionConsumerResponse::LeaseMutationStatus(Ok(
                    SessionConsumerLeaseMutationStatus::NotFound,
                )),
                calls: AtomicUsize::new(0),
            });
            let (client, server) = receipt_client(service.clone()).await;
            assert_eq!(
                client
                    .lease_mutation_status_with_budget(&service.expected, receipt_budget())
                    .await,
                Ok(SessionConsumerLeaseMutationStatus::NotFound)
            );
            assert_eq!(service.calls.load(Ordering::SeqCst), 1);
            server.abort_and_wait().await;
        }
    })
    .await;
}
