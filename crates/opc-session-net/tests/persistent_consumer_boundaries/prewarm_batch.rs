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
            config.clone(),
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
