//! Sequential activation setup must not consume an unused lane's idle budget.

use super::*;
use opc_session_net::SessionConsumerPreparedFencedTransitionBackend;
use opc_session_store::AtomicFencedTransitionCapability;
use tokio::sync::{oneshot, Notify};

struct ActivationConsumer;

#[async_trait]
impl SessionQuorumConsumer for ActivationConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        assert!(matches!(
            request.operation(),
            SessionConsumerOperation::FencedTransitionCapability
        ));
        SessionConsumerResponse::FencedTransitionCapability(Ok(
            AtomicFencedTransitionCapability::V1,
        ))
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Ok(stream::pending().boxed())
    }
}

struct IndependentServer {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl IndependentServer {
    async fn start(server: SessionQuorumConsumerServer) -> (Self, SocketAddr) {
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("independent server runtime")
                .block_on(async move {
                    let (handle, address) = server
                        .listen("127.0.0.1:0".parse().expect("listen address"))
                        .await
                        .expect("authenticated consumer listener");
                    ready_tx.send(address).expect("server address receiver");
                    let _ = stop_rx.await;
                    handle.abort_and_wait().await;
                });
        });
        let server = Self {
            stop: Some(stop_tx),
            thread: Some(thread),
        };
        (server, ready_rx.await.expect("server started"))
    }
}

impl Drop for IndependentServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("independent server stopped");
        }
    }
}

// Keep an I/O anchor runnable while real TCP/TLS work completes. Only the
// explicit advance in the scenario may move the client's protocol clock.
async fn without_clock_advance<F: std::future::Future>(future: F) -> F::Output {
    let started = tokio::time::Instant::now();
    let wall_started = std::time::Instant::now();
    tokio::pin!(future);
    loop {
        assert_eq!(tokio::time::Instant::now(), started);
        assert!(
            wall_started.elapsed() < Duration::from_secs(5),
            "authenticated loopback fixture stalled"
        );
        tokio::select! {
            biased;
            result = &mut future => return result,
            _ = tokio::task::yield_now() => {}
        }
    }
}

#[tokio::test]
async fn sequential_activation_prewarm_publishes_unused_lanes_as_one_batch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("batch-prewarm-server");
    let client_spiffe = spiffe("batch-prewarm-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_and_scope(&client_spiffe, &server_spiffe).await;
    let (_server, address) = IndependentServer::start(SessionQuorumConsumerServer::new(
        Arc::new(ActivationConsumer),
        pki.server_config(&server_spiffe),
        authorizer,
    ))
    .await;
    let tls = pki.client_config(&client_spiffe);
    let config = PersistentSessionConsumerConfig::try_new(
        2,
        4,
        Duration::from_millis(250),
        1,
        Duration::from_millis(600),
        2,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("bounded two-lane configuration");

    tokio::time::pause();
    let mut outcomes = Vec::new();
    for idle_timeout in [Duration::from_secs(5), Duration::from_millis(10)] {
        let resolutions = Arc::new(AtomicUsize::new(0));
        let second_entered = Arc::new(Notify::new());
        let second_release = Arc::new(Notify::new());
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            let second_entered = Arc::clone(&second_entered);
            let second_release = Arc::clone(&second_release);
            Arc::new(move || {
                let resolutions = Arc::clone(&resolutions);
                let second_entered = Arc::clone(&second_entered);
                let second_release = Arc::clone(&second_release);
                Box::pin(async move {
                    if resolutions.fetch_add(1, Ordering::SeqCst) == 1 {
                        second_entered.notify_one();
                        second_release.notified().await;
                    }
                    Ok(address)
                })
            })
        };
        let client = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new_with_resolver(
                resolver,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                voter_authority.clone(),
                tls.clone(),
            )
            .with_operation_timeout(Duration::from_millis(250))
            .with_idle_timeout(idle_timeout),
            config,
        )
        .expect("persistent client");
        let activation = {
            let client = client.clone();
            tokio::spawn(async move {
                SessionConsumerPreparedFencedTransitionBackend::persistent_exact_voter_prewarm_roster(
                    [client],
                )
                .await
            })
        };
        without_clock_advance(second_entered.notified()).await;
        let before = client.diagnostics().await;
        assert_eq!(before.setup_attempts, 2);
        assert_eq!(before.setup_successes, 1);
        assert_eq!(before.setup_failures, 0);
        let started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(25)).await;
        let delayed = client.diagnostics().await;
        second_release.notify_one();
        let activated = without_clock_advance(activation)
            .await
            .expect("activation task");
        assert_eq!(started.elapsed(), Duration::from_millis(25));
        let readiness = client.readiness().await;
        let completed = client.diagnostics().await;
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(completed.setup_successes, 2);
        assert_eq!(completed.setup_failures, 0);
        assert!(completed.max_active <= 2);
        eprintln!(
            "idle={idle_timeout:?} first_idle={}->{} setups={}/{} ready={}/{} activation={activated:?}",
            before.idle,
            delayed.idle,
            completed.setup_successes,
            completed.setup_failures,
            readiness.ready_request_connections,
            readiness.configured_request_connections,
        );
        outcomes.push((idle_timeout, readiness, activated.is_ok()));
        without_clock_advance(client.shutdown()).await;
    }
    tokio::time::resume();
    for (idle_timeout, readiness, activated) in outcomes {
        assert_eq!(readiness.configured_request_connections, 2);
        assert_eq!(
            readiness.ready_request_connections, 2,
            "unused activation lanes must survive sequential setup with {idle_timeout:?} idle"
        );
        assert!(readiness.ready);
        assert!(
            activated,
            "exact-width activation with {idle_timeout:?} idle"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_prewarm_never_counts_a_lane_after_its_peer_idle_deadline() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let pki = TestPki::new();
    let server_spiffe = spiffe("peer-idle-batch-server");
    let client_spiffe = spiffe("peer-idle-batch-client");
    let (authorizer, _scope, voter_authority) =
        authorizer_and_scope(&client_spiffe, &server_spiffe).await;
    let idle_timeout = Duration::from_secs(5);
    let (server, address) = SessionQuorumConsumerServer::new(
        Arc::new(ActivationConsumer),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_idle_timeout(idle_timeout)
    .listen("127.0.0.1:0".parse().expect("listen address"))
    .await
    .expect("authenticated consumer listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let second_entered = Arc::new(Notify::new());
    let second_release = Arc::new(Notify::new());
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        let second_entered = Arc::clone(&second_entered);
        let second_release = Arc::clone(&second_release);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            let second_entered = Arc::clone(&second_entered);
            let second_release = Arc::clone(&second_release);
            Box::pin(async move {
                if resolutions.fetch_add(1, Ordering::SeqCst) == 1 {
                    second_entered.notify_one();
                    second_release.notified().await;
                }
                Ok(address)
            })
        })
    };
    let config = PersistentSessionConsumerConfig::try_new(
        2,
        4,
        Duration::from_millis(250),
        1,
        Duration::from_millis(600),
        2,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("bounded two-lane configuration");
    let client = PersistentSessionConsumerClient::try_from_stateless(
        StatelessSessionConsumerClient::new_with_resolver(
            resolver,
            rustls_pki_types::ServerName::IpAddress(address.ip().into()),
            voter_authority,
            pki.client_config(&client_spiffe),
        )
        .with_operation_timeout(Duration::from_millis(250))
        .with_idle_timeout(idle_timeout),
        config,
    )
    .expect("persistent client");
    pause_client_clock_at_tick(runtime_origin).await;
    let first_hello_at = tokio::time::Instant::now();
    let prewarm = {
        let client = client.clone();
        tokio::spawn(async move { client.prewarm().await })
    };
    without_clock_advance(second_entered.notified()).await;
    let staged = client.diagnostics().await;
    assert_eq!(staged.setup_successes, 1);
    assert_eq!(staged.setup_attempts, 2);
    assert_eq!(server.admission_snapshot().active_connections, 1);
    tokio::time::advance(Duration::from_millis(25)).await;
    second_release.notify_one();
    let published = without_clock_advance(prewarm)
        .await
        .expect("prewarm task")
        .expect("both authenticated lanes published");
    assert!(published.ready);
    assert_eq!(published.ready_request_connections, 2);
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(server.admission_snapshot().active_connections, 2);
    let publication = tokio::time::Instant::now();
    assert_eq!(publication - first_hello_at, Duration::from_millis(25));

    // Both endpoints share the explicitly driven clock. The first real peer
    // idle deadline has elapsed; a safe client may already have retired both
    // lanes conservatively. The fixture never injects EOF or closes a socket.
    tokio::time::advance(idle_timeout - Duration::from_millis(24)).await;
    without_clock_advance(async {
        while server.admission_snapshot().active_connections >= 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        tokio::time::Instant::now() - first_hello_at,
        idle_timeout + Duration::from_millis(1)
    );
    assert!(tokio::time::Instant::now() < publication + idle_timeout);
    let peer_live = server.admission_snapshot().active_connections;
    let readiness = client.readiness().await;
    eprintln!(
        "peer_idle elapsed_ms={} peer_live={peer_live} ready={}/{}",
        first_hello_at.elapsed().as_millis(),
        readiness.ready_request_connections,
        readiness.configured_request_connections,
    );
    without_clock_advance(client.shutdown()).await;
    without_clock_advance(server.abort_and_wait()).await;
    assert!(peer_live < 2);
    assert!(
        readiness.ready_request_connections <= peer_live as usize,
        "a peer-closed unused lane must not count toward exact-width readiness"
    );
    assert!(!readiness.ready);
}

struct InterruptedBatch {
    server: Option<IndependentServer>,
    client: PersistentSessionConsumerClient,
    second_entered: Arc<Notify>,
    resolutions: Arc<AtomicUsize>,
}

impl InterruptedBatch {
    async fn new(lifecycle: ConnectionLifecyclePolicy) -> Self {
        let pki = TestPki::new();
        let server_spiffe = spiffe("interrupted-batch-server");
        let client_spiffe = spiffe("interrupted-batch-client");
        let (authorizer, _scope, voter_authority) =
            authorizer_and_scope(&client_spiffe, &server_spiffe).await;
        let (server, address) = IndependentServer::start(SessionQuorumConsumerServer::new(
            Arc::new(ActivationConsumer),
            pki.server_config(&server_spiffe),
            authorizer,
        ))
        .await;
        let resolutions = Arc::new(AtomicUsize::new(0));
        let second_entered = Arc::new(Notify::new());
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            let second_entered = Arc::clone(&second_entered);
            Arc::new(move || {
                let resolutions = Arc::clone(&resolutions);
                let second_entered = Arc::clone(&second_entered);
                Box::pin(async move {
                    if resolutions.fetch_add(1, Ordering::SeqCst) == 1 {
                        second_entered.notify_one();
                        std::future::pending::<()>().await;
                    }
                    Ok(address)
                })
            })
        };
        let config = PersistentSessionConsumerConfig::try_new(
            2,
            4,
            Duration::from_millis(250),
            1,
            Duration::from_millis(600),
            2,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("bounded interrupted-batch configuration");
        let client = PersistentSessionConsumerClient::try_from_stateless(
            StatelessSessionConsumerClient::new_with_resolver(
                resolver,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                voter_authority,
                pki.client_config(&client_spiffe),
            )
            .with_operation_timeout(Duration::from_millis(250))
            .with_idle_timeout(Duration::from_millis(10))
            .with_connection_lifecycle(lifecycle),
            config,
        )
        .expect("interrupted-batch client");
        Self {
            server: Some(server),
            client,
            second_entered,
            resolutions,
        }
    }

    async fn start(&self) -> tokio::task::JoinHandle<Result<(), opc_session_store::StoreError>> {
        let client = self.client.clone();
        let activation = tokio::spawn(async move {
            SessionConsumerPreparedFencedTransitionBackend::persistent_exact_voter_prewarm_roster([
                client,
            ])
            .await
            .map(|_| ())
        });
        without_clock_advance(self.second_entered.notified()).await;
        let diagnostics = self.client.diagnostics().await;
        assert_eq!(diagnostics.setup_attempts, 2);
        assert_eq!(diagnostics.setup_successes, 1);
        assert_eq!(diagnostics.setup_failures, 0);
        assert_eq!(diagnostics.active, 1);
        assert_eq!(diagnostics.idle, 0, "the unused lane is still staged");
        activation
    }

    async fn assert_no_retained_capacity(&self) {
        let readiness = self.client.readiness().await;
        assert!(!readiness.ready);
        assert_eq!(readiness.configured_request_connections, 2);
        assert_eq!(readiness.ready_request_connections, 0);
        let diagnostics = self.client.diagnostics().await;
        assert_eq!(diagnostics.active, 0);
        assert_eq!(diagnostics.idle, 0);
        assert_eq!(diagnostics.inflight, 0);
        assert_eq!(diagnostics.queued, 0);
        assert_eq!(diagnostics.pool_wait_current, 0);
        assert!(diagnostics.max_active <= 2);
    }
}

async fn assert_activation_unavailable(
    activation: tokio::task::JoinHandle<Result<(), opc_session_store::StoreError>>,
) {
    let result = without_clock_advance(activation)
        .await
        .expect("activation task");
    assert!(matches!(
        result,
        Err(opc_session_store::StoreError::BackendUnavailable(message))
            if message == "authenticated consumer activation readiness unavailable"
    ));
}

// Keep setup on normal time, then align the paused client to its runtime's
// original timer tick. Tokio rounds timer registrations up to milliseconds;
// an arbitrary pause instant would leave the exact 25/600 ms boundary below
// the registered tick while the I/O anchor correctly prevents auto-advance.
async fn pause_client_clock_at_tick(runtime_origin: tokio::time::Instant) {
    tokio::time::pause();
    let now = tokio::time::Instant::now();
    let next_tick = u64::try_from((now - runtime_origin).as_millis())
        .expect("fixture duration fits milliseconds")
        + 1;
    let aligned = runtime_origin + Duration::from_millis(next_tick);
    tokio::time::advance(aligned - now).await;
    assert_eq!(tokio::time::Instant::now(), aligned);
}

#[tokio::test(start_paused = true)]
async fn cancelled_prewarm_publishes_survivors_and_releases_admission() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_secs(1),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("bounded lifecycle with a deterministic retry interval");
    let fixture = InterruptedBatch::new(lifecycle).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let activation = fixture.start().await;
    tokio::time::advance(Duration::from_millis(25)).await;
    activation.abort();
    assert!(without_clock_advance(activation)
        .await
        .expect_err("activation cancelled")
        .is_cancelled());

    let partial = fixture.client.readiness().await;
    assert!(!partial.ready);
    assert_eq!(partial.ready_request_connections, 1);
    let cancelled = fixture.client.diagnostics().await;
    assert_eq!(cancelled.active, 1);
    assert_eq!(cancelled.idle, 1);
    assert_eq!(cancelled.setup_successes, 1);
    assert_eq!(cancelled.setup_failures, 1);
    assert_eq!(cancelled.queued, 0);

    tokio::time::advance(Duration::from_millis(9)).await;
    assert_eq!(
        fixture.client.readiness().await.ready_request_connections,
        1
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    fixture.assert_no_retained_capacity().await;
    let recovered = without_clock_advance(fixture.client.prewarm())
        .await
        .expect("cancelled prewarm releases every logical and physical admission");
    assert!(recovered.ready);
    assert_eq!(recovered.ready_request_connections, 2);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 4);
    let completed = fixture.client.diagnostics().await;
    assert_eq!(completed.setup_successes, 3);
    assert_eq!(completed.setup_failures, 1);
    assert_eq!(completed.active, 2);
    assert!(completed.max_active <= 2);
    without_clock_advance(fixture.client.shutdown()).await;
    fixture.assert_no_retained_capacity().await;
}

#[test]
fn cancelled_prewarm_outside_runtime_releases_admission_and_expires_survivors() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("client runtime");
    let fixture = runtime.block_on(async {
        let origin = tokio::time::Instant::now();
        tokio::time::resume();
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::ZERO,
        )
        .expect("bounded lifecycle with a deterministic retry interval");
        let fixture = InterruptedBatch::new(lifecycle).await;
        pause_client_clock_at_tick(origin).await;
        fixture
    });
    let mut prewarm = Box::pin(fixture.client.prewarm());
    runtime.block_on(async {
        without_clock_advance(async {
            tokio::select! {
                biased;
                result = &mut prewarm => panic!("second resolver must remain pending: {result:?}"),
                _ = fixture.second_entered.notified() => {}
            }
        })
        .await;
        let staged = fixture.client.diagnostics().await;
        assert_eq!(staged.setup_attempts, 2);
        assert_eq!(staged.setup_successes, 1);
        assert_eq!(staged.setup_failures, 0);
        assert_eq!(staged.active, 1);
        assert_eq!(staged.idle, 0);
        tokio::time::advance(Duration::from_millis(25)).await;
    });

    assert!(tokio::runtime::Handle::try_current().is_err());
    let cancelled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(prewarm)));
    if cancelled.is_err() {
        // Retain the production panic as the RED while closing the real TLS
        // transport before the fixture and its independent runtime exit.
        runtime.block_on(without_clock_advance(fixture.client.shutdown()));
    }
    assert!(
        cancelled.is_ok(),
        "dropping a pending prewarm outside Runtime::block_on must not panic"
    );
    assert!(tokio::runtime::Handle::try_current().is_err());

    runtime.block_on(async {
        let partial = fixture.client.readiness().await;
        assert!(!partial.ready);
        assert_eq!(partial.configured_request_connections, 2);
        assert_eq!(partial.ready_request_connections, 1);
        let cancelled = fixture.client.diagnostics().await;
        assert_eq!(cancelled.active, 1);
        assert_eq!(cancelled.idle, 1);
        assert_eq!(cancelled.setup_successes, 1);
        assert_eq!(cancelled.setup_failures, 1);
        assert_eq!(cancelled.inflight, 0);
        assert_eq!(cancelled.queued, 0);
        assert_eq!(cancelled.pool_wait_current, 0);

        tokio::time::advance(Duration::from_millis(9)).await;
        assert_eq!(
            fixture.client.readiness().await.ready_request_connections,
            1
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        fixture.assert_no_retained_capacity().await;
        let recovered = without_clock_advance(fixture.client.prewarm())
            .await
            .expect("outside-runtime cancellation releases every admission");
        assert!(recovered.ready);
        assert_eq!(recovered.ready_request_connections, 2);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 4);
        let completed = fixture.client.diagnostics().await;
        assert_eq!(completed.setup_successes, 3);
        assert_eq!(completed.setup_failures, 1);
        assert_eq!(completed.active, 2);
        assert!(completed.max_active <= 2);
        without_clock_advance(fixture.client.shutdown()).await;
        fixture.assert_no_retained_capacity().await;
    });
}

#[test]
fn cancelled_prewarm_after_runtime_shutdown_releases_admission() {
    let reconnect_backoff = Duration::from_millis(1);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("client runtime");
    let fixture = runtime.block_on(async {
        let origin = tokio::time::Instant::now();
        tokio::time::resume();
        let lifecycle = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(1),
            reconnect_backoff,
            reconnect_backoff,
            Duration::ZERO,
        )
        .expect("bounded lifecycle with a deterministic retry interval");
        let fixture = InterruptedBatch::new(lifecycle).await;
        pause_client_clock_at_tick(origin).await;
        fixture
    });
    let mut prewarm = Box::pin(fixture.client.prewarm());
    runtime.block_on(async {
        without_clock_advance(async {
            tokio::select! {
                biased;
                result = &mut prewarm => panic!("second resolver must remain pending: {result:?}"),
                _ = fixture.second_entered.notified() => {}
            }
        })
        .await;
        let staged = fixture.client.diagnostics().await;
        assert_eq!(staged.setup_attempts, 2);
        assert_eq!(staged.setup_successes, 1);
        assert_eq!(staged.active, 1);
        assert_eq!(staged.idle, 0);
    });
    drop(runtime);
    assert!(tokio::runtime::Handle::try_current().is_err());
    let cancelled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(prewarm)));
    let replacement_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("replacement client runtime");
    if cancelled.is_err() {
        replacement_runtime.block_on(without_clock_advance(fixture.client.shutdown()));
    }
    assert!(
        cancelled.is_ok(),
        "cancellation after the originating runtime exits must not panic"
    );
    replacement_runtime.block_on(async {
        fixture.assert_no_retained_capacity().await;
        assert_eq!(fixture.client.diagnostics().await.setup_attempts, 2);
        // Cancelling the in-progress setup retains its ordinary reconnect
        // cooldown. Advance that configured interval before freezing the
        // replacement runtime for the next real TLS setup.
        let released_at = tokio::time::Instant::now();
        tokio::time::advance(reconnect_backoff).await;
        assert_eq!(released_at.elapsed(), reconnect_backoff);
        let recovered = without_clock_advance(fixture.client.prewarm())
            .await
            .expect("retired runtime leaves no prewarm or transport admission behind");
        assert!(recovered.ready);
        assert_eq!(recovered.ready_request_connections, 2);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 4);
        let completed = fixture.client.diagnostics().await;
        assert_eq!(completed.setup_successes, 3);
        assert_eq!(completed.setup_failures, 1);
        assert_eq!(completed.active, 2);
        assert!(completed.max_active <= 2);
        without_clock_advance(fixture.client.shutdown()).await;
        fixture.assert_no_retained_capacity().await;
    });
}

#[tokio::test(start_paused = true)]
async fn expired_setup_bound_cannot_activate_a_partial_prewarm_batch() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = InterruptedBatch::new(ConnectionLifecyclePolicy::default()).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let started = tokio::time::Instant::now();
    let activation = fixture.start().await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(Duration::from_millis(599)).await;
    assert!(!activation.is_finished());
    assert_eq!(fixture.client.diagnostics().await.active, 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_activation_unavailable(activation).await;
    assert_eq!(started.elapsed(), Duration::from_millis(600));
    let partial = fixture.client.readiness().await;
    assert!(!partial.ready);
    assert_eq!(partial.configured_request_connections, 2);
    assert_eq!(partial.ready_request_connections, 1);
    let diagnostics = fixture.client.diagnostics().await;
    assert_eq!(diagnostics.setup_attempts, 2);
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.setup_failures, 1);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    without_clock_advance(fixture.client.shutdown()).await;
    fixture.assert_no_retained_capacity().await;
}

#[tokio::test(start_paused = true)]
async fn staged_prewarm_lane_retires_at_its_absolute_lifecycle_bound() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_millis(31),
        Duration::from_millis(6),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("absolute retirement at 25 ms after authentication");
    let fixture = InterruptedBatch::new(lifecycle).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let started = tokio::time::Instant::now();
    let activation = fixture.start().await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(Duration::from_millis(24)).await;
    assert!(!activation.is_finished());
    assert_eq!(fixture.client.diagnostics().await.active, 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_activation_unavailable(activation).await;
    assert_eq!(started.elapsed(), Duration::from_millis(25));
    fixture.assert_no_retained_capacity().await;
    let diagnostics = fixture.client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.setup_failures, 1);
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    without_clock_advance(fixture.client.shutdown()).await;
}

#[tokio::test(start_paused = true)]
async fn staged_prewarm_lane_cannot_survive_peer_closure() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let mut fixture = InterruptedBatch::new(ConnectionLifecyclePolicy::default()).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let activation = fixture.start().await;
    drop(fixture.server.take());
    assert_activation_unavailable(activation).await;
    fixture.assert_no_retained_capacity().await;
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.client.diagnostics().await.setup_successes, 1);
    without_clock_advance(fixture.client.shutdown()).await;
}

#[tokio::test(start_paused = true)]
async fn staged_prewarm_lane_cannot_survive_explicit_reauthentication() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = InterruptedBatch::new(ConnectionLifecyclePolicy::default()).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let activation = fixture.start().await;
    fixture
        .client
        .request_reauthentication()
        .expect("advance authenticated generation");
    assert_activation_unavailable(activation).await;
    fixture.assert_no_retained_capacity().await;
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
    without_clock_advance(fixture.client.shutdown()).await;
}

#[tokio::test(start_paused = true)]
async fn staged_prewarm_lane_cannot_publish_after_shutdown() {
    let runtime_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let fixture = InterruptedBatch::new(ConnectionLifecyclePolicy::default()).await;
    pause_client_clock_at_tick(runtime_origin).await;
    let activation = fixture.start().await;
    let report = without_clock_advance(fixture.client.shutdown()).await;
    assert_activation_unavailable(activation).await;
    assert_eq!(report.forced_calls, 0);
    assert_eq!(report.forced_watches, 0);
    fixture.assert_no_retained_capacity().await;
    assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 2);
}
