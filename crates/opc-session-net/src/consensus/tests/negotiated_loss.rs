use super::*;

struct Fixture {
    peer: RemoteSessionConsensusPeer,
    remote: Option<tokio::io::DuplexStream>,
    resolutions: Arc<AtomicUsize>,
    resolution_entered: Arc<Notify>,
    release_resolution: Arc<Notify>,
}

impl Fixture {
    async fn new(staged: bool) -> Self {
        let (_, binding) = bindings();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let resolution_entered = Arc::new(Notify::new());
        let release_resolution = Arc::new(Notify::new());
        let resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            let entered = Arc::clone(&resolution_entered);
            let release = Arc::clone(&release_resolution);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "test resolver",
                    ))
                })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&binding, resolver),
            None,
            binding,
            None,
        );
        let now = tokio::time::Instant::now();
        let epoch = peer.cold_connector().epoch();
        let attempt_id = uuid::Uuid::new_v4();
        let (local, remote) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(local);
        let connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            admission_attempt_id: Some(attempt_id),
            lifecycle: ConnectionLifecycle::new(peer.lifecycle_policy, now, None, None, 0, None)
                .expect("fixture lifecycle"),
            last_successful_correlated_use: None,
            idle_deadline_origin: now,
        };
        if staged {
            peer.connection_pool
                .cold_connection
                .state
                .lock()
                .await
                .phase = ConsensusColdConnectionPhase::Ready {
                attempt_id,
                epoch,
                connection: Box::new(connection),
            };
        } else {
            *peer.connection_pool.primary.connection.lock().await = Some(connection);
        }
        Self {
            peer,
            remote: Some(remote),
            resolutions,
            resolution_entered,
            release_resolution,
        }
    }

    fn call(
        &self,
        budget: Duration,
    ) -> tokio::task::JoinHandle<Result<SessionConsensusWireResponse, SessionConsensusPeerError>>
    {
        let peer = self.peer.clone();
        let request = SessionConsensusWireRequest::try_new(
            peer.consensus_identity(),
            peer.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"negotiated-loss".to_vec(),
        )
        .expect("bounded request");
        tokio::spawn(async move { peer.call_with_timeout(request, budget).await })
    }

    async fn receive_call_id(&mut self) -> uuid::Uuid {
        let request: SessionConsensusTransportRequest = read_frame(
            self.remote.as_mut().expect("live remote"),
            MIN_SESSION_CONSENSUS_FRAME_SIZE,
        )
        .await
        .expect("complete negotiated request");
        let SessionConsensusTransportRequest::Call { call_id, .. } = request else {
            panic!("AppendEntries must use the ordinary consensus transport request");
        };
        call_id
    }

    async fn assert_shared_cooldown(self) {
        assert!(self
            .peer
            .connection_pool
            .primary
            .connection
            .lock()
            .await
            .is_none());
        let loss_at = tokio::time::Instant::now();
        let budget = Duration::from_millis(10);
        let retry = self.call(budget);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            self.resolutions.load(Ordering::SeqCst),
            0,
            "a lost negotiated socket must not immediately start another physical setup"
        );
        tokio::time::advance(budget).await;
        assert_eq!(
            retry.await.expect("join short retry"),
            Err(SessionConsensusPeerError::Timeout)
        );
        assert_eq!(tokio::time::Instant::now(), loss_at + budget);
        assert_eq!(self.resolutions.load(Ordering::SeqCst), 0);

        let cooldown = self.peer.lifecycle_policy.reconnect_backoff_min();
        let edge = Duration::from_millis(1);
        tokio::time::advance(cooldown - budget - edge).await;
        tokio::task::yield_now().await;
        assert_eq!(self.resolutions.load(Ordering::SeqCst), 0);
        tokio::time::advance(edge).await;
        self.resolution_entered.notified().await;
        assert_eq!(tokio::time::Instant::now(), loss_at + cooldown);
        assert_eq!(self.resolutions.load(Ordering::SeqCst), 1);

        // The original caller has already expired. Settle the independently
        // bounded setup it joined, without renewing that caller's budget.
        self.release_resolution.notify_one();
        let coordinator = &self.peer.connection_pool.cold_connection;
        tokio::time::timeout(
            DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout(),
            async {
                loop {
                    let changed = coordinator.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if matches!(
                        coordinator.state.lock().await.phase,
                        ConsensusColdConnectionPhase::Failed { .. }
                    ) {
                        break;
                    }
                    changed.await;
                }
            },
        )
        .await
        .expect("owned setup must settle");
        assert_eq!(self.resolutions.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn timed_out_negotiated_calls_share_reconnect_cooldown() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        fixture.receive_call_id().await;
        tokio::time::advance(Duration::from_millis(20)).await;
        assert_eq!(
            call.await.expect("join timed-out call"),
            Err(SessionConsensusPeerError::Timeout)
        );
        fixture.assert_shared_cooldown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn disconnected_negotiated_calls_share_reconnect_cooldown() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        fixture.receive_call_id().await;
        drop(fixture.remote.take());
        assert_eq!(
            call.await.expect("join disconnected call"),
            Err(SessionConsensusPeerError::Unavailable)
        );
        fixture.assert_shared_cooldown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_negotiated_calls_share_reconnect_cooldown() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        fixture.receive_call_id().await;
        call.abort();
        assert!(call.await.expect_err("join cancelled call").is_cancelled());
        fixture.assert_shared_cooldown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn uncorrelated_negotiated_responses_share_reconnect_cooldown() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        fixture.receive_call_id().await;
        write_frame(
            fixture.remote.as_mut().expect("live remote"),
            &SessionConsensusTransportResponse::Call {
                call_id: uuid::Uuid::new_v4(),
                response: SessionConsensusWireResponse {
                    result: Ok(Vec::new()),
                },
            },
        )
        .await
        .expect("write uncorrelated response");
        assert_eq!(
            call.await.expect("join uncorrelated call"),
            Err(SessionConsensusPeerError::Protocol)
        );
        fixture.assert_shared_cooldown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_predecessor_does_not_cool_down_new_epoch() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        fixture.receive_call_id().await;
        fixture
            .peer
            .reauthentication
            .request_reauthentication()
            .expect("advance reauthentication epoch");
        let generation = fixture.peer.reauthentication.generation();
        let gate = &fixture.peer.connection_pool.reconnect_gate;
        gate.observe_epoch(generation, None);
        call.abort();
        assert!(call
            .await
            .expect_err("join cancelled predecessor")
            .is_cancelled());
        let now = tokio::time::Instant::now();
        let ReconnectAdmission::Admitted(attempt) = gate
            .acquire_classified(now + Duration::from_millis(10), generation, None)
            .await
        else {
            panic!("a late negotiated loss cannot cool down the newer epoch");
        };
        attempt.succeeded();
        assert_eq!(tokio::time::Instant::now(), now);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn correlated_unavailable_response_preserves_reuse_without_cooldown() {
    let _metrics = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for staged in [false, true] {
        let mut fixture = Fixture::new(staged).await;
        let call = fixture.call(Duration::from_millis(20));
        let call_id = fixture.receive_call_id().await;
        let response = SessionConsensusWireResponse {
            result: Err(SessionConsensusPeerError::Unavailable),
        };
        write_frame(
            fixture.remote.as_mut().expect("live remote"),
            &SessionConsensusTransportResponse::Call {
                call_id,
                response: response.clone(),
            },
        )
        .await
        .expect("write complete response");
        assert_eq!(call.await.expect("join correlated call"), Ok(response));
        assert!(fixture
            .peer
            .connection_pool
            .primary
            .connection
            .lock()
            .await
            .is_some());
        let now = tokio::time::Instant::now();
        let ReconnectAdmission::Admitted(attempt) = fixture
            .peer
            .connection_pool
            .reconnect_gate
            .acquire_classified(now + Duration::from_millis(10), 0, None)
            .await
        else {
            panic!("a complete correlated semantic error must not publish a loss cooldown");
        };
        attempt.succeeded();
        assert_eq!(tokio::time::Instant::now(), now);
        assert_eq!(fixture.resolutions.load(Ordering::SeqCst), 0);
    }
}
