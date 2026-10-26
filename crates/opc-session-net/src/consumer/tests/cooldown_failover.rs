use super::*;
use crate::ReconnectCooldownPolicy;

fn cooled_client(
    policy: ReconnectCooldownPolicy,
    timeout: Duration,
) -> (PersistentSessionConsumerClient, RotatableClientMaterial) {
    let (client, material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = client
        .with_operation_timeout(timeout)
        .with_connection_lifecycle(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::ZERO,
            )
            .expect("bounded cooldown"),
        );
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        client,
        PersistentSessionConsumerConfig {
            reconnect_jitter: Duration::ZERO,
            ..PersistentSessionConsumerConfig::default()
        }
        .with_cooldown_admission(policy),
    )
    .expect("persistent client");
    persistent.pool.reconnect_control.publish_connection_loss(
        persistent.pool.client.reauthentication.generation(),
        Some(persistent.pool.client.tls_config.material_status().epoch()),
    );
    (persistent, material)
}

async fn lease() -> LeaseGuard {
    let SessionConsumerOperation::AcquireLease { key, owner, ttl } =
        mutation_request(SessionConsumerRequestId::new())
            .operation()
            .clone()
    else {
        panic!("lease fixture");
    };
    FakeSessionBackend::new()
        .acquire(&key, owner, ttl)
        .await
        .expect("synthetic lease")
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_returns_delete_and_release_before_either_wait() {
    let lease = lease().await;
    // One deadline ends within cooldown (the consumer's second wait), the
    // other ends after cooldown (the lifecycle gate's first wait).
    for timeout in [Duration::from_millis(100), Duration::from_secs(2)] {
        let (client, _material) = cooled_client(ReconnectCooldownPolicy::FailOver, timeout);
        let before = tokio::time::Instant::now();
        assert!(
            matches!(
                client
                    .delete_fenced_with_id(SessionConsumerRequestId::new(), &lease)
                    .now_or_never(),
                Some(Err(SessionConsumerMutationError::NotTransmitted {
                    cause: SessionConsumerClientError::Cooldown { .. },
                }))
            ),
            "cooldown must return a pre-write result without a timer"
        );
        assert!(matches!(
            client
                .release_with_id(SessionConsumerRequestId::new(), &lease)
                .now_or_never(),
            Some(Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Cooldown { .. },
            }))
        ));
        assert_eq!(tokio::time::Instant::now(), before);
        assert_eq!(client.diagnostics().await.resolve_attempts, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_returns_v2_before_either_wait() {
    for timeout in [Duration::from_millis(100), Duration::from_secs(2)] {
        let (client, _material) = cooled_client(ReconnectCooldownPolicy::FailOver, timeout);
        let request = SessionConsumerV2Request::new(
            scope(),
            SessionConsumerV2Operation::FencedTransitionV2Capability,
        );
        assert!(matches!(
            client.execute_v2(&request).now_or_never(),
            Some(Err(
                PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                    cause: SessionConsumerClientError::Cooldown { .. },
                }
            ))
        ));
        assert_eq!(client.v2_pool.setup_attempts.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_keeps_single_peer_waiting_by_default() {
    assert_eq!(
        PersistentSessionConsumerConfig::default().cooldown_admission(),
        ReconnectCooldownPolicy::Wait,
    );
    let (client, _material) =
        cooled_client(ReconnectCooldownPolicy::Wait, Duration::from_millis(100));
    let lease = lease().await;
    let request_id = SessionConsumerRequestId::new();
    let call = client.delete_fenced_with_id(request_id, &lease);
    tokio::pin!(call);
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(matches!(
        call.await,
        Err(SessionConsumerMutationError::NotTransmitted { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_serializes_one_probe_and_keeps_shared_backoff() {
    let (client, _material) =
        cooled_client(ReconnectCooldownPolicy::FailOver, Duration::from_secs(2));
    let control = &client.pool.reconnect_control;
    let generation = client.pool.client.reauthentication.generation();
    let material = client.pool.client.tls_config.material_status().epoch();
    let start = tokio::time::Instant::now();
    let acquire = || control.acquire(start + Duration::from_secs(5), generation, material);
    for result in futures_util::future::join_all((0..16).map(|_| acquire())).await {
        assert!(matches!(
            result,
            Err(SessionConsumerClientError::Cooldown { .. })
        ));
    }
    assert_eq!(tokio::time::Instant::now(), start);
    assert_eq!(
        control.gate.remaining_cooldown(),
        Duration::from_millis(500)
    );
    tokio::time::advance(Duration::from_millis(500)).await;
    let probe = acquire().await.expect("one probe at expiry");
    for result in futures_util::future::join_all((0..16).map(|_| acquire())).await {
        assert!(matches!(
            result,
            Err(SessionConsumerClientError::Cooldown { .. })
        ));
    }
    probe.failed();
    assert_eq!(control.gate.remaining_cooldown(), Duration::from_secs(1));
    assert!(matches!(
        acquire().now_or_never(),
        Some(Err(SessionConsumerClientError::Cooldown { .. }))
    ));
    tokio::time::advance(Duration::from_secs(1)).await;
    acquire().await.expect("one recovery probe").succeeded();
    assert_eq!(control.gate.remaining_cooldown(), Duration::ZERO);
    acquire().await.expect("recovered peer is usable").failed();
    assert_eq!(
        control.gate.remaining_cooldown(),
        Duration::from_millis(500)
    );
}

// Keep Tokio's clock fixed while real TLS sockets make progress. A separate
// wall-clock watchdog detects a missing wake or accidental timer dependency.
async fn without_time<T>(future: impl std::future::Future<Output = T>) -> T {
    let started = std::time::Instant::now();
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            value = &mut future => return value,
            _ = tokio::task::yield_now() => {
                assert!(started.elapsed() < Duration::from_secs(5), "operation waited on frozen time");
            }
        }
    }
}

struct DeleteReleaseConsumer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl SessionQuorumConsumer for DeleteReleaseConsumer {
    async fn execute(
        &self,
        _authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.0.fetch_add(1, Ordering::SeqCst);
        match request.operation() {
            SessionConsumerOperation::DeleteFenced { .. } => {
                SessionConsumerResponse::DeleteFenced(Ok(()))
            }
            SessionConsumerOperation::ReleaseLease { .. } => {
                SessionConsumerResponse::ReleaseLease(Ok(()))
            }
            _ => panic!("only delete and release may be dispatched"),
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

#[tokio::test]
async fn cooldown_failover_concurrent_delete_release_reach_healthy_voter_without_time() {
    let identities = [
        material_spiffe("cooled"),
        material_spiffe("healthy"),
        material_spiffe("third"),
    ];
    let roster = test_consumer_roster_for(&identities);
    for (ordinal, member) in roster.consensus_members().enumerate() {
        assert_eq!(
            roster.voter(member.node_id()).expect("voter").ordinal(),
            ordinal
        );
    }
    let client_identity = material_spiffe("routed-client");
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let grant = opc_session_store::SessionConsumerAuthorizationGrant::try_new(
        client_identity,
        [SessionConsumerTenantNfScope::new(
            TenantId::new("wire-test").expect("tenant"),
            NetworkFunctionKind::smf(),
        )],
    )
    .expect("grant");
    let healthy_authority = voter_authority_for_identity(&roster, &identities[1]);
    let authorizer = SessionConsumerAuthorizer::try_new(
        roster
            .clone()
            .authorization_manifest(healthy_authority.node_id(), [grant])
            .expect("manifest"),
    )
    .expect("authorizer");
    let calls = Arc::new(AtomicUsize::new(0));
    let (server, address) = SessionQuorumConsumerServer::new(
        Arc::new(DeleteReleaseConsumer(Arc::clone(&calls))),
        material.trusted_server_config(identities[1].as_str()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().expect("address"))
    .await
    .expect("server");
    let config = PersistentSessionConsumerConfig::default()
        .with_cooldown_admission(ReconnectCooldownPolicy::FailOver);
    let client = |authority| {
        PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new(
                address,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                authority,
                material.config(),
            ),
            config,
        )
        .expect("client")
    };
    let cooled = client(voter_authority_for_identity(&roster, &identities[0]));
    let healthy = client(healthy_authority);
    healthy.prewarm().await.expect("healthy lanes");
    let lease = lease().await;
    tokio::time::pause();
    let before = tokio::time::Instant::now();
    cooled.pool.reconnect_control.publish_connection_loss(
        cooled.pool.client.reauthentication.generation(),
        Some(cooled.pool.client.tls_config.material_status().epoch()),
    );
    without_time(futures_util::future::join_all((0..8).map(|_| async {
        let delete_id = SessionConsumerRequestId::new();
        assert!(matches!(
            cooled.delete_fenced_with_id(delete_id, &lease).await,
            Err(SessionConsumerMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Cooldown { .. }
            })
        ));
        assert_eq!(
            healthy.delete_fenced_with_id(delete_id, &lease).await,
            Ok(())
        );
        let release_id = SessionConsumerRequestId::new();
        assert!(matches!(
            cooled.release_with_id(release_id, &lease).await,
            Err(SessionConsumerLeaseMutationError::NotTransmitted {
                cause: SessionConsumerClientError::Cooldown { .. }
            })
        ));
        assert_eq!(healthy.release_with_id(release_id, &lease).await, Ok(()));
    })))
    .await;
    assert_eq!(tokio::time::Instant::now(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 16);
    assert_eq!(cooled.diagnostics().await.resolve_attempts, 0);
    without_time(healthy.shutdown()).await;
    without_time(cooled.shutdown()).await;
    without_time(server.abort_and_wait()).await;
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_prepared_success_and_possible_write_receipt_only() {
    for mutation in [
        PublicProtectedFencedMutationBehavior::CommitAndReply,
        PublicProtectedFencedMutationBehavior::CommitThenLoseResponse,
    ] {
        let fixture = without_time(public_protected_fenced_acceptance_fixture_with_config(
            [PublicProtectedFencedStatusBehavior::Recorded; 3],
            [PublicProtectedFencedPreflightBehavior::Available; 3],
            None,
            [None; 3],
            PersistentSessionConsumerConfig::default()
                .with_cooldown_admission(ReconnectCooldownPolicy::FailOver),
            mutation,
        ))
        .await;
        let before = tokio::time::Instant::now();
        let first = &fixture.composite.router.clients[0];
        first.pool.idle.lock().expect("idle").clear();
        first.pool.reconnect_control.publish_connection_loss(
            first.pool.client.reauthentication.generation(),
            Some(first.pool.client.tls_config.material_status().epoch()),
        );
        let cooldown = first.pool.reconnect_control.gate.remaining_cooldown();
        assert!(
            matches!(
                first
                    .reserve_retained_request_lane_before(
                        before + Duration::from_millis(10),
                        false,
                    )
                    .now_or_never(),
                Some(Err(SessionConsumerClientError::Cooldown { .. }))
            ),
            "prepared cooldown admission must return before polling any timer"
        );
        let request = public_protected_fenced_request_on_a(&fixture.composite, 0x4d);
        let request_id = request.request_id();
        let deadline = before + Duration::from_secs(1);
        let mut prepared = without_time(fixture.composite.prepare_fenced_transition(
            request,
            PreparedCheckpointBudget::new(deadline, Duration::from_millis(10)).expect("budget"),
        ))
        .await
        .expect("prepare");
        if matches!(
            mutation,
            PublicProtectedFencedMutationBehavior::CommitAndReply
        ) {
            assert!(without_time(prepared.execute_once()).await.is_ok());
            assert_eq!(tokio::time::Instant::now(), before);
        } else {
            let mut execute = Box::pin(prepared.execute_once());
            without_time(async {
                loop {
                    assert!(futures_util::poll!(&mut execute).is_pending());
                    if fixture.mutation_calls[1].load(Ordering::SeqCst) == 1 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert_eq!(
                tokio::time::Instant::now(),
                before,
                "B accepted before A's cooldown"
            );
            tokio::time::advance(Duration::from_millis(10)).await;
            assert_eq!(
                without_time(&mut execute).await,
                Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
            );
            drop(execute);
            assert!(before.elapsed() < cooldown);
        }
        assert_eq!(
            fixture
                .mutation_calls
                .each_ref()
                .map(|count| count.load(Ordering::SeqCst)),
            [0, 1, 0]
        );
        // Once a write is possible the same opaque token cannot send another
        // mutation. The exact receipt is the only permitted recovery path.
        assert_eq!(
            without_time(prepared.execute_once()).await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        if matches!(
            mutation,
            PublicProtectedFencedMutationBehavior::CommitThenLoseResponse
        ) {
            assert!(matches!(
                without_time(prepared.status_until_terminal(deadline)).await,
                Ok(FencedTransitionStatus::Recorded(_))
            ));
            assert_eq!(
                fixture
                    .mutation_calls
                    .each_ref()
                    .map(|count| count.load(Ordering::SeqCst)),
                [0, 1, 0]
            );
        }
        without_time(fixture.shutdown()).await;
    }
}

async fn concurrent_prepared_retained_setup(policy: ReconnectCooldownPolicy) {
    let mut fixture = without_time(public_protected_fenced_acceptance_fixture_with_config(
        [PublicProtectedFencedStatusBehavior::Recorded; 3],
        [PublicProtectedFencedPreflightBehavior::Available; 3],
        None,
        [None; 3],
        PersistentSessionConsumerConfig {
            reconnect_jitter: Duration::ZERO,
            ..PersistentSessionConsumerConfig::default()
        }
        .with_cooldown_admission(policy),
        PublicProtectedFencedMutationBehavior::CommitAndReply,
    ))
    .await;

    // Keep A's address, but hold its replacement at TLS instead of completing
    // Hello. Both affine callers still select the same exact activated voter.
    without_time(fixture.servers.remove(0).abort_and_wait()).await;
    let listener = tokio::net::TcpListener::bind(fixture.addresses[0])
        .await
        .expect("replacement listener");
    let first = &fixture.composite.router.clients[0];
    first
        .request_reauthentication()
        .expect("retire A's authenticated lanes");
    first.pool.idle.lock().expect("idle").clear();
    first.pool.reconnect_control.publish_connection_loss(
        first.pool.client.reauthentication.generation(),
        Some(first.pool.client.tls_config.material_status().epoch()),
    );
    let cooldown = first.pool.reconnect_control.gate.remaining_cooldown();
    assert!(!cooldown.is_zero());
    tokio::time::advance(cooldown).await;
    let before = tokio::time::Instant::now();
    assert!(first.pool.reconnect_control.gate.can_probe_now());

    let request_a = public_protected_fenced_request_on_a(&fixture.composite, 0x60);
    let request_b = public_protected_fenced_request_on_a(&fixture.composite, 0x80);
    assert_ne!(request_a.request_id(), request_b.request_id());
    let budget =
        PreparedCheckpointBudget::new(before + Duration::from_secs(1), Duration::from_millis(10))
            .expect("original prepared deadline and physical cap");
    let mut prepared_a = without_time(
        fixture
            .composite
            .prepare_fenced_transition(request_a, budget),
    )
    .await
    .expect("first prepared caller");
    let mut prepared_b = without_time(
        fixture
            .composite
            .prepare_fenced_transition(request_b, budget),
    )
    .await
    .expect("second prepared caller");
    let diagnostics_before = first.diagnostics().await;
    let mut execute_a = Box::pin(prepared_a.execute_once());
    let (held_socket, _) = without_time(async {
        let accept = listener.accept();
        tokio::pin!(accept);
        loop {
            assert!(futures_util::poll!(&mut execute_a).is_pending());
            if let std::task::Poll::Ready(accepted) = futures_util::poll!(&mut accept) {
                break accepted.expect("A receives the first reconnect probe");
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    without_time(async {
        loop {
            assert!(futures_util::poll!(&mut execute_a).is_pending());
            if first.diagnostics().await.tls_attempts > diagnostics_before.tls_attempts {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let flight = first
        .pool
        .retained_warm_lane
        .lock()
        .expect("retained setup")
        .as_ref()
        .expect("first caller publishes its setup flight")
        .clone();
    assert!(flight.result().is_none());
    assert!(!first.pool.reconnect_control.gate.can_probe_now());
    let flight_owners = Arc::strong_count(&flight);
    let mut execute_b = Box::pin(prepared_b.execute_once());

    if policy == ReconnectCooldownPolicy::FailOver {
        assert!(without_time(&mut execute_b).await.is_ok());
        assert_eq!(fixture.mutation_calls[1].load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&flight), flight_owners);
    } else {
        // The default policy still joins the retained flight and waits for
        // its owner. Observe the join itself, rather than an unrelated yield.
        without_time(async {
            loop {
                assert!(futures_util::poll!(&mut execute_b).is_pending());
                if Arc::strong_count(&flight) > flight_owners {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(Arc::strong_count(&flight), flight_owners + 1);
        assert_eq!(fixture.mutation_calls[1].load(Ordering::SeqCst), 0);
    }

    assert_eq!(tokio::time::Instant::now(), before);
    assert!(futures_util::poll!(&mut execute_a).is_pending());
    assert!(flight.result().is_none());
    assert!(!first.pool.reconnect_control.gate.can_probe_now());
    let held = first.diagnostics().await;
    assert_eq!(held.setup_attempts, diagnostics_before.setup_attempts + 1);
    assert_eq!(held.tcp_attempts, diagnostics_before.tcp_attempts + 1);
    assert_eq!(held.tls_attempts, diagnostics_before.tls_attempts + 1);
    assert_eq!(held.hello_attempts, diagnostics_before.hello_attempts);
    assert_eq!(fixture.mutation_calls[0].load(Ordering::SeqCst), 0);
    assert_eq!(fixture.mutation_calls[2].load(Ordering::SeqCst), 0);

    // A single failed probe publishes one shared backoff. The owner and any
    // waiting follower then finish through B without a second setup at A.
    drop(held_socket);
    if policy == ReconnectCooldownPolicy::Wait {
        let (result_a, result_b) =
            without_time(futures_util::future::join(&mut execute_a, &mut execute_b)).await;
        assert!(result_a.is_ok());
        assert!(result_b.is_ok());
    } else {
        assert!(without_time(&mut execute_a).await.is_ok());
    }
    drop(execute_a);
    drop(execute_b);
    assert_eq!(tokio::time::Instant::now(), before);
    assert_eq!(
        first.diagnostics().await.setup_attempts,
        diagnostics_before.setup_attempts + 1,
    );
    assert_eq!(
        first.pool.reconnect_control.gate.remaining_cooldown(),
        cooldown
            .saturating_mul(2)
            .min(first.pool.client.lifecycle_policy.reconnect_backoff_max()),
    );
    assert_eq!(
        fixture
            .mutation_calls
            .each_ref()
            .map(|calls| calls.load(Ordering::SeqCst)),
        [0, 2, 0],
    );
    drop(listener);
    drop(prepared_a);
    drop(prepared_b);
    without_time(fixture.shutdown()).await;
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_concurrent_prepared_bypasses_pending_retained_setup() {
    concurrent_prepared_retained_setup(ReconnectCooldownPolicy::FailOver).await;
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_concurrent_prepared_default_waits_for_pending_retained_setup() {
    concurrent_prepared_retained_setup(ReconnectCooldownPolicy::Wait).await;
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_prepared_admission_precedes_dns() {
    let (mut client, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let resolves = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&resolves);
    client.resolve = Arc::new(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    });
    let persistent = PersistentSessionConsumerClient::try_from_stateless(
        client,
        PersistentSessionConsumerConfig::default()
            .with_cooldown_admission(ReconnectCooldownPolicy::FailOver),
    )
    .unwrap();
    persistent.pool.reconnect_control.publish_connection_loss(
        persistent.pool.client.reauthentication.generation(),
        Some(persistent.pool.client.tls_config.material_status().epoch()),
    );
    let before = tokio::time::Instant::now();
    assert!(matches!(
        persistent
            .establish_one_retained_request_lane(before + Duration::from_secs(1))
            .now_or_never(),
        Some(Err(SessionConsumerClientError::Cooldown { .. }))
    ));
    assert_eq!(resolves.load(Ordering::SeqCst), 0);
    assert_eq!(tokio::time::Instant::now(), before);
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_prepared_admission_precedes_pool_permits() {
    let (client, _material) =
        cooled_client(ReconnectCooldownPolicy::FailOver, Duration::from_secs(2));
    let held = Arc::clone(&client.pool.prewarm)
        .try_acquire_owned()
        .unwrap();
    let before = tokio::time::Instant::now();
    assert!(matches!(
        client
            .establish_one_retained_request_lane(before + Duration::from_secs(1))
            .now_or_never(),
        Some(Err(SessionConsumerClientError::Cooldown { .. }))
    ));
    assert_eq!(tokio::time::Instant::now(), before);
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn cooldown_failover_prepared_admission_declines_pending_warm_setup() {
    let (client, _material) =
        cooled_client(ReconnectCooldownPolicy::FailOver, Duration::from_secs(2));
    let Ok(Ok(leader)) = client.pool.begin_warm_lane() else {
        panic!("first caller owns warm setup");
    };
    let before = tokio::time::Instant::now();
    assert!(matches!(
        client
            .ensure_warm_request_capacity_before(before + Duration::from_secs(1))
            .now_or_never(),
        Some(Err(SessionConsumerClientError::Cooldown { .. }))
    ));
    assert_eq!(tokio::time::Instant::now(), before);
    drop(leader);
}
