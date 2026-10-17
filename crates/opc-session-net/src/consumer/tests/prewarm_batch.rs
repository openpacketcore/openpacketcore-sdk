use super::*;
use crate::consumer::PersistentPrewarmBatch;
use crate::lifecycle::{CertificateExpiryEvidence, TlsCompletionTime};

struct ReviewReadyAtPeerBoundWriter {
    ready_at: tokio::time::Instant,
    accepted_bytes: Arc<AtomicUsize>,
    accepted_writes: Arc<AtomicU64>,
}

impl AsyncWrite for ReviewReadyAtPeerBoundWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if tokio::time::Instant::now() < self.ready_at {
            return Poll::Pending;
        }
        if !bytes.is_empty() {
            self.accepted_bytes.fetch_add(bytes.len(), Ordering::SeqCst);
            self.accepted_writes.fetch_add(1, Ordering::Release);
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn review_resume_first_write_at_peer_bound(watch: bool) {
    let (client, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = client
        .with_idle_timeout(Duration::from_millis(100))
        .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10));
    let started = tokio::time::Instant::now();
    let operation_deadline = started + Duration::from_millis(250);
    let accepted_bytes = Arc::new(AtomicUsize::new(0));
    let accepted_writes = Arc::new(AtomicU64::new(0));
    let (mut connection, _) = synthetic_consumer_connection(
        &client,
        operation_deadline,
        Box::new(ReviewReadyAtPeerBoundWriter {
            ready_at: started + Duration::from_millis(90),
            accepted_bytes: Arc::clone(&accepted_bytes),
            accepted_writes: Arc::clone(&accepted_writes),
        }),
    );
    connection.accepted_ciphertext_writes = Arc::clone(&accepted_writes);
    assert_eq!(
        connection.peer_first_call_deadline,
        started + Duration::from_millis(90)
    );
    let result = if watch {
        let request = SessionConsumerRequest::new(
            scope(),
            SessionConsumerRequestId::new(),
            SessionConsumerOperation::Watch { start_sequence: 0 },
        );
        let mut reauthentication = client.reauthentication.subscribe();
        let mut material = Some(client.tls_config.subscribe_material_changes());
        let write = client.write_watch_call_on_connection(
            &mut connection,
            &request,
            operation_deadline,
            false,
            &mut reauthentication,
            &mut material,
        );
        tokio::pin!(write);
        assert!(write.as_mut().now_or_never().is_none());
        assert_eq!(accepted_bytes.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_millis(90)).await;
        format!("{:?}", write.await)
    } else {
        let request = mutation_request(SessionConsumerRequestId::new());
        let write = client.execute_on_connection(
            &mut connection,
            &request,
            operation_deadline,
            false,
            operation_deadline,
            None,
        );
        tokio::pin!(write);
        assert!(write.as_mut().now_or_never().is_none());
        assert_eq!(accepted_bytes.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_millis(90)).await;
        format!("{:?}", write.await)
    };
    assert_eq!(
        tokio::time::Instant::now(),
        connection.peer_first_call_deadline
    );
    eprintln!(
        "review peer-bound resume watch={watch} elapsed_ms={} bytes={} writes={} result={result}",
        started.elapsed().as_millis(),
        accepted_bytes.load(Ordering::SeqCst),
        accepted_writes.load(Ordering::SeqCst)
    );
    assert_eq!(
        accepted_bytes.load(Ordering::SeqCst),
        0,
        "a pending first write must not transmit when resumed at the peer bound"
    );
    assert_eq!(accepted_writes.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn review_first_call_request_resume_at_peer_bound_writes_nothing() {
    review_resume_first_write_at_peer_bound(false).await;
}

#[tokio::test(start_paused = true)]
async fn review_first_call_watch_resume_at_peer_bound_writes_nothing() {
    review_resume_first_write_at_peer_bound(true).await;
}

#[derive(Clone, Copy, Debug)]
enum FirstCallPollBoundary {
    PendingWrite,
    PartialWrite,
    BufferedFlush,
    PartialFlush,
}

struct FirstCallBoundaryWriter {
    boundary: FirstCallPollBoundary,
    ready_at: tokio::time::Instant,
    accepted_bytes: Arc<AtomicUsize>,
    accepted_writes: Arc<AtomicU64>,
    buffered_bytes: Arc<AtomicUsize>,
}

impl FirstCallBoundaryWriter {
    fn accept(&self, count: usize) {
        if count != 0 {
            self.accepted_bytes.fetch_add(count, Ordering::SeqCst);
            self.accepted_writes.fetch_add(1, Ordering::Release);
        }
    }
}

impl AsyncWrite for FirstCallBoundaryWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(
            self.boundary,
            FirstCallPollBoundary::BufferedFlush | FirstCallPollBoundary::PartialFlush
        ) {
            // Model TLS accepting plaintext without any lower-socket write.
            self.buffered_bytes.fetch_add(bytes.len(), Ordering::SeqCst);
            return Poll::Ready(Ok(bytes.len()));
        }
        if matches!(self.boundary, FirstCallPollBoundary::PartialWrite)
            && self.accepted_writes.load(Ordering::Acquire) == 0
        {
            let count = bytes.len().min(1);
            self.accept(count);
            return Poll::Ready(Ok(count));
        }
        if tokio::time::Instant::now() < self.ready_at {
            return Poll::Pending;
        }
        self.accept(bytes.len());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.boundary, FirstCallPollBoundary::PartialFlush)
            && self.accepted_writes.load(Ordering::Acquire) == 0
        {
            assert!(self.buffered_bytes.load(Ordering::SeqCst) > 1);
            self.buffered_bytes.fetch_sub(1, Ordering::SeqCst);
            self.accept(1);
            return Poll::Pending;
        }
        if tokio::time::Instant::now() < self.ready_at {
            return Poll::Pending;
        }
        self.accept(self.buffered_bytes.swap(0, Ordering::SeqCst));
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
    }
}

async fn assert_first_call_poll_boundary(watch: bool) {
    for resumed_ms in [90, 91] {
        for boundary in [
            FirstCallPollBoundary::PendingWrite,
            FirstCallPollBoundary::PartialWrite,
            FirstCallPollBoundary::BufferedFlush,
            FirstCallPollBoundary::PartialFlush,
        ] {
            let (client, _material) = stateless_test_client(SessionReauthenticationControl::new());
            let client = client
                .with_idle_timeout(Duration::from_millis(100))
                .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10));
            let started = tokio::time::Instant::now();
            let operation_deadline = started + Duration::from_millis(250);
            let accepted_bytes = Arc::new(AtomicUsize::new(0));
            let accepted_writes = Arc::new(AtomicU64::new(0));
            let buffered_bytes = Arc::new(AtomicUsize::new(0));
            let (mut connection, _) = synthetic_consumer_connection(
                &client,
                operation_deadline,
                Box::new(FirstCallBoundaryWriter {
                    boundary,
                    ready_at: started + Duration::from_millis(90),
                    accepted_bytes: Arc::clone(&accepted_bytes),
                    accepted_writes: Arc::clone(&accepted_writes),
                    buffered_bytes: Arc::clone(&buffered_bytes),
                }),
            );
            connection.accepted_ciphertext_writes = Arc::clone(&accepted_writes);
            assert_eq!(
                connection.peer_first_call_deadline,
                started + Duration::from_millis(90)
            );
            let partial = matches!(
                boundary,
                FirstCallPollBoundary::PartialWrite | FirstCallPollBoundary::PartialFlush
            );
            let before_expiry = usize::from(partial);
            let result = {
                let write = async {
                    if watch {
                        let request = SessionConsumerRequest::new(
                            scope(),
                            SessionConsumerRequestId::new(),
                            SessionConsumerOperation::Watch { start_sequence: 0 },
                        );
                        let mut reauthentication = client.reauthentication.subscribe();
                        let mut material = Some(client.tls_config.subscribe_material_changes());
                        let progress = FrameWriteProgress::new();
                        client
                            .write_watch_call_on_connection_classified(
                                &mut connection,
                                &request,
                                operation_deadline,
                                false,
                                ConsumerRotationReceivers {
                                    reauthentication: &mut reauthentication,
                                    material: &mut material,
                                },
                                &progress,
                            )
                            .await
                            .map(|_| ())
                    } else {
                        let request = mutation_request(SessionConsumerRequestId::new());
                        client
                            .execute_on_connection(
                                &mut connection,
                                &request,
                                operation_deadline,
                                false,
                                operation_deadline,
                                None,
                            )
                            .await
                            .map(|_| ())
                    }
                };
                tokio::pin!(write);
                assert!(write.as_mut().now_or_never().is_none());
                assert_eq!(accepted_bytes.load(Ordering::SeqCst), before_expiry);
                assert_eq!(accepted_writes.load(Ordering::SeqCst), u64::from(partial));
                let buffered = buffered_bytes.load(Ordering::SeqCst);
                assert_eq!(
                    buffered > 0,
                    matches!(
                        boundary,
                        FirstCallPollBoundary::BufferedFlush | FirstCallPollBoundary::PartialFlush
                    )
                );
                tokio::time::advance(Duration::from_millis(89)).await;
                assert!(write.as_mut().now_or_never().is_none());
                assert_eq!(accepted_bytes.load(Ordering::SeqCst), before_expiry);
                tokio::time::advance(Duration::from_millis(resumed_ms - 89)).await;
                let result = write.await;
                assert_eq!(
                    buffered_bytes.load(Ordering::SeqCst),
                    buffered,
                    "expiry must not flush buffered TLS output"
                );
                result
            };
            let expected = if partial {
                SessionConsumerCallError::MayHaveSent(SessionConsumerClientError::Deadline)
            } else {
                SessionConsumerCallError::BeforeCallWrite(SessionConsumerClientError::Deadline)
            };
            assert_eq!(
                result,
                Err(expected),
                "watch={watch} boundary={boundary:?} resumed_ms={resumed_ms}"
            );
            assert_eq!(
                accepted_bytes.load(Ordering::SeqCst),
                before_expiry,
                "no additional byte may be accepted at or after expiry"
            );
            assert_eq!(accepted_writes.load(Ordering::SeqCst), u64::from(partial));
            assert_eq!(
                connection.calls, 1,
                "the attempted Call reserved one correlation"
            );
            assert_eq!(started.elapsed(), Duration::from_millis(resumed_ms));
            eprintln!("first_call_poll_boundary watch={watch} boundary={boundary:?} elapsed_ms={resumed_ms} accepted_bytes={before_expiry} result={result:?}");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn first_call_request_pending_write_and_flush_obey_peer_bound() {
    assert_first_call_poll_boundary(false).await;
}

#[tokio::test(start_paused = true)]
async fn first_call_watch_pending_write_and_flush_obey_peer_bound() {
    assert_first_call_poll_boundary(true).await;
}

fn staged_connection(
    client: &PersistentSessionConsumerClient,
) -> (ConsumerConnection, tokio::io::DuplexStream) {
    let (mut connection, _) = synthetic_consumer_connection(
        &client.pool.client,
        tokio::time::Instant::now() + Duration::from_millis(1),
        Box::new(tokio::io::sink()),
    );
    let (reader, peer) = tokio::io::duplex(16);
    connection.reader = Box::new(reader);
    (connection, peer)
}

#[test]
fn prewarm_batch_drop_reaps_on_its_origin_runtime_without_a_pruning_api() {
    for enter_other_runtime in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("origin runtime");
        let (client, batch, _peer, deadline, _metrics_guard) = runtime.block_on(async {
            let metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
                .lock()
                .await;
            let (stateless, _material) =
                stateless_test_client(SessionReauthenticationControl::new());
            let client = PersistentSessionConsumerClient::try_from_stateless(
                stateless.with_idle_timeout(Duration::from_millis(10)),
                PersistentSessionConsumerConfig {
                    request_connections: 1,
                    ..PersistentSessionConsumerConfig::default()
                },
            )
            .expect("one physical lane");
            let (mut connection, peer) = staged_connection(&client);
            connection._persistent_physical_admission = Some(
                Arc::clone(&client.pool.physical_lanes)
                    .try_acquire_owned()
                    .expect("staged lane owns physical admission"),
            );
            let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
            batch.connections.push(connection);
            tokio::time::advance(Duration::from_millis(25)).await;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
            (client, batch, peer, deadline, metrics_guard)
        });

        assert!(tokio::runtime::Handle::try_current().is_err());
        let other_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("unrelated runtime");
        {
            let _other = enter_other_runtime.then(|| other_runtime.enter());
            drop(batch);
            assert_eq!(
                tokio::runtime::Handle::try_current().is_ok(),
                enter_other_runtime,
                "batch cleanup restores the caller's runtime context"
            );
        }
        drop(other_runtime);
        assert!(tokio::runtime::Handle::try_current().is_err());
        {
            let idle = client.pool.idle.lock().expect("published idle lane");
            assert_eq!(idle.len(), 1);
            assert_eq!(idle[0].idle_deadline, deadline);
            assert_eq!(client.pool.physical_lanes.available_permits(), 0);
        }
        runtime.block_on(async {
            wait_for_idle_reaper_armed_deadline(&client, deadline, "outside-runtime cancellation")
                .await;
            tokio::time::advance(Duration::from_millis(9)).await;
            wait_for_raw_idle_count(&client, 1).await;
            assert_eq!(client.pool.physical_lanes.available_permits(), 0);
            tokio::time::advance(Duration::from_millis(1)).await;
            wait_for_raw_idle_count(&client, 0).await;
            assert_eq!(client.pool.physical_lanes.available_permits(), 1);
            client.shutdown().await;
        });
    }
}

#[test]
fn prewarm_batch_drop_after_tokio_thread_local_teardown_discards_admission() {
    struct ThreadExitBatch {
        batch: Option<PersistentPrewarmBatch>,
        result: std::sync::mpsc::Sender<(bool, bool)>,
    }

    impl Drop for ThreadExitBatch {
        fn drop(&mut self) {
            let context_destroyed = tokio::runtime::Handle::try_current()
                .is_err_and(|error| error.is_thread_local_destroyed());
            // Catch the production panic inside the TLS destructor so the
            // regression reports a normal test failure instead of aborting.
            let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(self.batch.take());
            }));
            let _ = self.result.send((context_destroyed, dropped.is_ok()));
        }
    }

    thread_local! {
        static THREAD_EXIT_BATCH: std::cell::RefCell<Option<ThreadExitBatch>> =
            const { std::cell::RefCell::new(None) };
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("live origin runtime");
    let (client, batch, _peer, _metrics_guard) = runtime.block_on(async {
        let metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
        let client = PersistentSessionConsumerClient::try_from_stateless(
            stateless,
            PersistentSessionConsumerConfig {
                request_connections: 1,
                ..PersistentSessionConsumerConfig::default()
            },
        )
        .expect("one physical lane");
        let (mut connection, peer) = staged_connection(&client);
        connection._persistent_physical_admission = Some(
            Arc::clone(&client.pool.physical_lanes)
                .try_acquire_owned()
                .expect("staged lane owns physical admission"),
        );
        let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
        batch.connections.push(connection);
        (client, batch, peer, metrics_guard)
    });
    assert_eq!(client.pool.physical_lanes.available_permits(), 0);
    let handle = runtime.handle().clone();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // TLS destructors run in reverse initialization order. Initialize
        // our owner first, then Tokio's context on this otherwise fresh thread.
        THREAD_EXIT_BATCH.with(|slot| {
            *slot.borrow_mut() = Some(ThreadExitBatch {
                batch: Some(batch),
                result: result_tx,
            });
        });
        drop(handle.enter());
    })
    .join()
    .expect("thread exits without an uncaught destructor panic");
    let (context_destroyed, dropped) = result_rx.recv().expect("TLS destructor ran");
    assert!(
        context_destroyed,
        "fixture must run after Tokio TLS teardown"
    );
    assert_eq!(client.pool.physical_lanes.available_permits(), 1);
    assert!(client.pool.idle.lock().expect("raw idle lanes").is_empty());
    runtime.block_on(client.shutdown());
    assert!(
        dropped,
        "dropping a prewarm batch after Tokio TLS teardown must not panic"
    );
}

#[tokio::test(start_paused = true)]
async fn prewarm_batch_publication_keeps_peer_and_used_lane_deadlines() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let policy = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(60),
        Duration::from_millis(975),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("bounded peer-expiry lifecycle");
    let client = PersistentSessionConsumerClient::try_from_stateless(
        stateless
            .with_idle_timeout(Duration::from_millis(10))
            .with_connection_lifecycle(policy),
        PersistentSessionConsumerConfig {
            request_connections: 3,
            ..PersistentSessionConsumerConfig::default()
        },
    )
    .expect("three lanes");
    let started = tokio::time::Instant::now();

    let (mut used, _used_peer) = staged_connection(&client);
    used.calls = 1;
    let used_deadline = started + Duration::from_millis(27);
    used.idle_deadline = used_deadline;
    client.pool.return_idle(used);

    let (mut first, _first_peer) = staged_connection(&client);
    let wall = Timestamp::now_utc();
    let expiry = wall.add_seconds(1).expect("peer certificate expiry");
    first.lifecycle = ConnectionLifecycle::new(
        policy,
        started,
        None,
        Some(CertificateExpiryEvidence::capture(
            expiry,
            expiry,
            TlsCompletionTime::for_test(started, wall),
        )),
        client.pool.client.reauthentication.generation(),
        Some(client.pool.client.tls_config.material_status().epoch()),
    )
    .expect("peer expires before the local unused-lane interval");
    let peer_lifecycle = first.lifecycle.clone();
    let peer_retire_at = started + Duration::from_millis(25);
    assert_eq!(peer_lifecycle.retire_at(), peer_retire_at);
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    batch.connections.push(first);
    tokio::time::advance(Duration::from_millis(20)).await;
    let (second, _second_peer) = staged_connection(&client);
    batch.connections.push(second);
    let publication_deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    drop(batch);

    assert!(client.readiness().await.ready);
    {
        let idle = client.pool.idle.lock().expect("idle lanes");
        assert_eq!(idle.len(), 3);
        assert_eq!(idle[0].calls, 1);
        assert_eq!(idle[0].idle_deadline, used_deadline);
        assert_eq!(idle[1].idle_deadline, publication_deadline);
        assert_eq!(idle[2].idle_deadline, publication_deadline);
        assert_eq!(idle[1].lifecycle.retire_at(), peer_retire_at);
        assert_eq!(
            idle[1]
                .lifecycle
                .hard_deadline()
                .expect("peer hard deadline"),
            started + Duration::from_secs(1)
        );
    }
    tokio::time::advance(Duration::from_millis(4)).await;
    assert_eq!(client.readiness().await.ready_request_connections, 3);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(client.readiness().await.ready_request_connections, 2);
    assert_eq!(
        peer_lifecycle.recorded_retirement_reason(),
        Some(RetirementReason::PeerLeafExpiry)
    );
    assert_eq!(peer_lifecycle.recorded_retirement_count(), 1);
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_eq!(client.readiness().await.ready_request_connections, 1);
    tokio::time::advance(Duration::from_millis(3)).await;
    assert_eq!(client.readiness().await.ready_request_connections, 0);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn prewarm_batch_publication_rejects_expired_stale_used_and_closed_lanes() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    for case in [
        "lifecycle",
        "reauthentication",
        "material",
        "address-generation",
        "shutdown",
        "used",
        "closed",
        "unsolicited-data",
    ] {
        let control = SessionReauthenticationControl::new();
        let (stateless, material) = stateless_test_client(control.clone());
        let client =
            PersistentSessionConsumerClient::from_stateless(stateless).expect("persistent client");
        let (mut connection, peer) = staged_connection(&client);
        let mut peer = Some(peer);
        match case {
            "lifecycle" => connection.lifecycle.expire_at_final_ack_boundary_for_test(),
            "reauthentication" => {
                control.request_reauthentication().expect("new generation");
            }
            "material" => material.rotate(),
            "address-generation" => {
                let original = connection.resolved_address;
                connection.warm_target_generation = client.pool.publish_warm_target(original);
                client
                    .pool
                    .publish_warm_target("127.0.0.1:2".parse().expect("second address"));
                client.pool.publish_warm_target(original);
            }
            "shutdown" => client.pool.start_shutdown(),
            "used" => {
                connection.calls = 1;
                connection.idle_deadline = tokio::time::Instant::now();
            }
            "closed" => drop(peer.take()),
            "unsolicited-data" => peer
                .as_mut()
                .expect("connected peer")
                .write_all(&[1])
                .await
                .expect("unexpected application data"),
            _ => unreachable!("fixed publication controls"),
        }
        let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
        batch.connections.push(connection);
        drop(batch);
        assert_eq!(
            client.readiness().await.ready_request_connections,
            0,
            "batch publication must reject {case}"
        );
        assert!(client.pool.idle.lock().expect("idle lanes").is_empty());
        client.shutdown().await;
    }
}

#[tokio::test(start_paused = true)]
async fn prewarm_batch_monitor_cannot_republish_a_consumed_peer_failure() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client =
        PersistentSessionConsumerClient::from_stateless(stateless).expect("persistent client");
    let (connection, mut peer) = staged_connection(&client);
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    batch.connections.push(connection);
    peer.write_all(&[1]).await.expect("unsolicited peer data");
    batch.retire_unusable().await;
    drop(batch);
    assert_eq!(client.readiness().await.ready_request_connections, 0);
    assert!(client.pool.idle.lock().expect("idle lanes").is_empty());
    assert_eq!(client.diagnostics().await.reconnects, 1);
    client.shutdown().await;
}

struct RotateMaterialOnProbe(Arc<RotatableClientMaterial>);

impl AsyncRead for RotateMaterialOnProbe {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.rotate();
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn prewarm_batch_rechecks_fresh_authentication_after_the_peer_probe() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, material) = stateless_test_client(SessionReauthenticationControl::new());
    let client =
        PersistentSessionConsumerClient::from_stateless(stateless).expect("persistent client");
    let (mut connection, _peer) = staged_connection(&client);
    let admitted_epoch = connection.lifecycle.admitted_material_epoch();
    connection.reader = Box::new(RotateMaterialOnProbe(Arc::new(material)));
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    batch.connections.push(connection);
    drop(batch);
    assert_ne!(
        admitted_epoch,
        Some(client.pool.client.tls_config.material_status().epoch())
    );
    assert_eq!(client.readiness().await.ready_request_connections, 0);
    assert!(client.pool.idle.lock().expect("idle lanes").is_empty());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn peer_idle_bound_accounts_for_ack_transit_and_rejects_exhausted_budgets() {
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = stateless
        .clone()
        .with_idle_timeout(Duration::from_millis(100))
        .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10));
    let hello_started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(25)).await;
    let ack_received = tokio::time::Instant::now();
    assert_eq!(
        client.peer_first_call_deadline(hello_started, ack_received),
        Ok(hello_started + Duration::from_millis(90)),
        "time spent receiving HelloAck cannot become extra peer idle time"
    );
    tokio::time::advance(Duration::from_millis(65)).await;
    assert_eq!(
        client.peer_first_call_deadline(hello_started, tokio::time::Instant::now()),
        Err(SessionConsumerClientError::Unavailable),
        "an acknowledgement arriving inside the safety margin is unusable"
    );
    for (local, peer, margin) in [
        (100, 0, 10),
        (100, 100, 0),
        (100, 100, 100),
        (100, 100, 101),
        (100, 5_001, 10),
        (101, 100, 10),
    ] {
        assert!(matches!(
            PersistentSessionConsumerClient::from_stateless(
                stateless
                    .clone()
                    .with_idle_timeout(Duration::from_millis(local))
                    .with_peer_idle_timeout(
                        Duration::from_millis(peer),
                        Duration::from_millis(margin),
                    ),
            ),
            Err(PersistentSessionConsumerConfigError::Timing)
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn prewarm_peer_idle_bound_reaps_each_lane_from_its_own_hello() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = PersistentSessionConsumerClient::try_from_stateless(
        stateless
            .with_idle_timeout(Duration::from_millis(100))
            .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10)),
        PersistentSessionConsumerConfig {
            request_connections: 2,
            ..PersistentSessionConsumerConfig::default()
        },
    )
    .expect("two lanes with an explicit peer bound");
    let started = tokio::time::Instant::now();
    let mut peers = Vec::new();
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    for index in 0..2 {
        if index == 1 {
            tokio::time::advance(Duration::from_millis(25)).await;
        }
        let (mut connection, peer) = staged_connection(&client);
        connection._persistent_physical_admission = Some(
            Arc::clone(&client.pool.physical_lanes)
                .try_acquire_owned()
                .expect("physical lane admission"),
        );
        batch.connections.push(connection);
        peers.push(peer);
    }
    drop(batch);
    {
        let idle = client.pool.idle.lock().expect("published batch");
        assert_eq!(idle.len(), 2);
        assert_eq!(idle[0].idle_deadline, started + Duration::from_millis(90));
        assert_eq!(idle[1].idle_deadline, started + Duration::from_millis(115));
    }
    wait_for_idle_reaper_armed_deadline(
        &client,
        started + Duration::from_millis(90),
        "first peer's deadline",
    )
    .await;
    tokio::time::advance(Duration::from_millis(64)).await;
    wait_for_raw_idle_count(&client, 2).await;
    assert_eq!(client.pool.physical_lanes.available_permits(), 0);
    tokio::time::advance(Duration::from_millis(1)).await;
    wait_for_raw_idle_count(&client, 1).await;
    assert_eq!(client.pool.physical_lanes.available_permits(), 1);
    wait_for_idle_reaper_armed_deadline(
        &client,
        started + Duration::from_millis(115),
        "second peer's deadline",
    )
    .await;
    tokio::time::advance(Duration::from_millis(25)).await;
    wait_for_raw_idle_count(&client, 0).await;
    assert_eq!(client.pool.physical_lanes.available_permits(), 2);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn prewarm_peer_idle_bound_ends_staging_before_peer_closure() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = PersistentSessionConsumerClient::from_stateless(
        stateless
            .with_idle_timeout(Duration::from_millis(100))
            .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10)),
    )
    .expect("explicit peer bound");
    let (mut connection, _live_peer) = staged_connection(&client);
    connection._persistent_physical_admission = Some(
        Arc::clone(&client.pool.physical_lanes)
            .try_acquire_owned()
            .expect("physical lane admission"),
    );
    let deadline = connection.peer_first_call_deadline;
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    batch.connections.push(connection);
    assert!(batch.retire_unusable().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(89)).await;
    assert!(batch.retire_unusable().now_or_never().is_none());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(batch.retire_unusable().now_or_never().is_some());
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert!(batch.connections.is_empty());
    drop(batch);
    assert!(client.pool.idle.lock().expect("raw idle lanes").is_empty());
    assert_eq!(
        client.pool.physical_lanes.available_permits(),
        client.pool.config.request_connections
    );
    assert!(!client.readiness().await.ready);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn prewarm_first_call_rechecks_peer_idle_bound_after_checkout() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let (stateless, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = PersistentSessionConsumerClient::from_stateless(
        stateless
            .with_idle_timeout(Duration::from_millis(100))
            .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10)),
    )
    .expect("explicit peer bound");
    let written = Arc::new(AtomicUsize::new(0));
    let (mut connection, _live_peer) = staged_connection(&client);
    connection.writer = Box::new(SharedCountingWriter {
        accepted: Arc::clone(&written),
    });
    let peer_deadline = connection.peer_first_call_deadline;
    let mut batch = PersistentPrewarmBatch::new(Arc::clone(&client.pool));
    batch.connections.push(connection);
    drop(batch);
    let mut checked_out = client.pool.take_idle().expect("lane is initially reusable");
    tokio::time::advance(Duration::from_millis(90)).await;
    assert_eq!(tokio::time::Instant::now(), peer_deadline);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    let connection = checked_out.connection_mut().expect("checked-out lane");
    let request = mutation_request(SessionConsumerRequestId::new());
    let result = client
        .pool
        .client
        .execute_on_connection(connection, &request, deadline, false, deadline, None)
        .await;
    assert_eq!(
        result,
        Err(SessionConsumerCallError::BeforeCallWrite(
            SessionConsumerClientError::Unavailable
        )),
        "an expired first Call must remain definitely untransmitted"
    );
    assert_eq!(connection.calls, 0);
    assert_eq!(written.load(Ordering::SeqCst), 0);
    let request = SessionConsumerRequest::new(
        scope(),
        SessionConsumerRequestId::new(),
        SessionConsumerOperation::Watch { start_sequence: 0 },
    );
    let mut reauthentication = client.pool.client.reauthentication.subscribe();
    let mut material = Some(client.pool.client.tls_config.subscribe_material_changes());
    assert_eq!(
        client
            .pool
            .client
            .write_watch_call_on_connection(
                connection,
                &request,
                deadline,
                false,
                &mut reauthentication,
                &mut material,
            )
            .await,
        Err(SessionConsumerClientError::Unavailable)
    );
    assert_eq!(connection.calls, 0);
    assert_eq!(written.load(Ordering::SeqCst), 0);
    drop(checked_out);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn prewarm_first_call_write_cannot_wait_past_its_peer_idle_bound() {
    let (client, _material) = stateless_test_client(SessionReauthenticationControl::new());
    let client = client
        .with_idle_timeout(Duration::from_millis(100))
        .with_peer_idle_timeout(Duration::from_millis(100), Duration::from_millis(10));
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_millis(250);
    let (mut connection, _) =
        synthetic_consumer_connection(&client, deadline, Box::new(PendingWriter));
    let request = mutation_request(SessionConsumerRequestId::new());
    let result = {
        let write = client.execute_on_connection(
            &mut connection,
            &request,
            deadline,
            false,
            deadline,
            None,
        );
        tokio::pin!(write);
        assert!(write.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(90)).await;
        write.await
    };
    assert_eq!(
        result,
        Err(SessionConsumerCallError::BeforeCallWrite(
            SessionConsumerClientError::Deadline
        ))
    );
    assert_eq!(
        tokio::time::Instant::now(),
        connection.peer_first_call_deadline
    );
    assert_eq!(
        connection.accepted_ciphertext_writes.load(Ordering::SeqCst),
        0
    );
}
