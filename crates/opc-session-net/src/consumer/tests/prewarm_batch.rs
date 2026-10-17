use super::*;
use crate::consumer::PersistentPrewarmBatch;
use crate::lifecycle::{CertificateExpiryEvidence, TlsCompletionTime};

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
