//! One accepted mTLS RPC expires, its late response hits a real closed socket,
//! and a read-barrier/head RPC must recover within the original parent budget.
use super::*;
use std::sync::OnceLock;
use tokio::sync::{mpsc, oneshot};

/// Passive observations of the production listener, never a replacement I/O
/// implementation. The duplicated descriptor only peeks for the client's FIN.
pub(crate) struct ConnectionObserver {
    first_accepted: StdMutex<Option<oneshot::Sender<TcpStream>>>,
    terminals: mpsc::UnboundedSender<Result<(), ProtocolError>>,
    connections: OnceLock<Arc<Semaphore>>,
    executions: OnceLock<Arc<Semaphore>>,
}

impl ConnectionObserver {
    pub(crate) fn observe_permits(
        &self,
        connections: &Arc<Semaphore>,
        executions: &Arc<Semaphore>,
    ) {
        self.connections.set(Arc::clone(connections)).unwrap();
        self.executions.set(Arc::clone(executions)).unwrap();
    }

    pub(crate) fn observe_accepted(&self, stream: TcpStream) -> TcpStream {
        let Some(sender) = self.first_accepted.lock().unwrap().take() else {
            return stream;
        };
        let stream = stream.into_std().expect("observe accepted TCP socket");
        let observer = TcpStream::from_std(stream.try_clone().expect("duplicate accepted socket"))
            .expect("register passive FIN observer");
        sender.send(observer).expect("publish accepted socket");
        TcpStream::from_std(stream).expect("restore production socket")
    }

    pub(crate) fn observe_terminal(&self, result: Result<(), ProtocolError>) {
        self.terminals
            .send(result)
            .expect("publish server terminal");
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ResponsiveHeadHandler {
    entered: Notify,
    release: Semaphore,
    calls: AtomicUsize,
}

#[cfg(target_os = "linux")]
#[async_trait]
impl SessionConsensusRpcHandler for ResponsiveHeadHandler {
    async fn handle(
        &self,
        _sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let payload = match request.family {
            SessionConsensusRpcFamily::AppendEntries => {
                self.entered.notify_one();
                self.release.acquire().await.unwrap().forget();
                // A small TLS response may fit in the socket buffer even after
                // FIN. A valid maximum-sized payload spans writes and exposes
                // the peer's real TCP reset without synthetic I/O errors.
                vec![0; opc_session_store::SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES]
            }
            SessionConsensusRpcFamily::ReadBarrier => {
                assert_eq!(request.payload, b"head");
                // A fixed responsive backend isolates connection recovery from
                // Raft apply/barrier latency and the consumer Watch protocol.
                80_u64.to_be_bytes().to_vec()
            }
            _ => panic!("unexpected RPC family"),
        };
        SessionConsensusWireResponse {
            result: Ok(payload),
        }
    }
}

#[cfg(target_os = "linux")]
fn assert_connection_counters(attempts: u64, successes: u64, transport_failures: u64) {
    assert_eq!(
        METRICS
            .session_net_connection_attempts
            .load(Ordering::Relaxed),
        attempts
    );
    assert_eq!(
        METRICS
            .session_net_connection_successes
            .load(Ordering::Relaxed),
        successes
    );
    assert_eq!(
        METRICS
            .session_net_connection_failure_transport
            .load(Ordering::Relaxed),
        transport_failures
    );
    for counter in [
        &METRICS.session_net_connection_failure_authentication,
        &METRICS.session_net_connection_failure_timeout,
        &METRICS.session_net_connection_failure_protocol,
        &METRICS.session_net_connection_failure_backend,
        &METRICS.session_net_connection_superseded,
        &METRICS.session_net_connection_abandoned,
        &METRICS.session_net_reconnect_failures,
        &METRICS.session_net_lifecycle_drain_overruns,
    ] {
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn expired_mtls_rpc_broken_pipe_recovers_head_with_original_parent_budget() {
    // Other unit tests also write these production counters. Run this one
    // scenario in an isolated child, using the same convention as the existing
    // connection-accounting tests.
    const CHILD: &str = "OPC_SESSION_NET_BROKEN_PIPE_RECOVERY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "consensus::tests::broken_pipe_recovery::expired_mtls_rpc_broken_pipe_recovers_head_with_original_parent_budget",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .expect("run isolated real-TLS recovery test");
        assert!(status.success(), "isolated real-TLS recovery test failed");
        return;
    }

    let descriptors = (1..=2)
        .map(|i| {
            QuorumReplicaDescriptor::new(
                ReplicaId::new(format!("replica-{i}")).unwrap(),
                ReplicaEndpoint::new(format!("replica-{i}.invalid"), 7443).unwrap(),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{i}"
                ))
                .unwrap(),
                ReplicaFailureDomain::new(format!("zone-{i}")).unwrap(),
                ReplicaBackingIdentity::new(format!("disk-{i}")).unwrap(),
            )
        })
        .collect();
    let manifest = Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("broken-pipe-recovery").unwrap(),
            SessionConfigurationGeneration::new("1").unwrap(),
            SessionConfigurationEpoch::new(1).unwrap(),
            descriptors,
        )
        .unwrap(),
    );
    let server_binding = manifest
        .bind_local(ReplicaId::new("replica-2").unwrap())
        .unwrap();
    let binding = manifest
        .bind_local(ReplicaId::new("replica-1").unwrap())
        .unwrap()
        .bind_remote(ReplicaId::new("replica-2").unwrap())
        .unwrap();
    let material = crate::test_support::RotatableServerMaterial::new(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/2",
    );
    let server_tls = material.config();
    let (client_source, client_tls) = material.trusted_client_config_with_source(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
    );
    for status in [server_tls.material_status(), client_tls.material_status()] {
        assert_eq!(
            status.availability(),
            opc_tls::TlsMaterialAvailability::Ready
        );
    }
    let server_epoch = server_tls.material_status().epoch();
    let client_epoch = client_tls.material_status().epoch();
    let handler = Arc::new(ResponsiveHeadHandler {
        entered: Notify::new(),
        release: Semaphore::new(0),
        calls: AtomicUsize::new(0),
    });
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (terminals_tx, mut terminals) = mpsc::unbounded_channel();
    let observer = Arc::new(ConnectionObserver {
        first_accepted: StdMutex::new(Some(accepted_tx)),
        terminals: terminals_tx,
        connections: OnceLock::new(),
        executions: OnceLock::new(),
    });
    let mut server =
        SessionConsensusServer::new(handler.clone(), server_tls.clone(), server_binding);
    let execution_limit = server.max_connections;
    server.connection_observer = Some(Arc::clone(&observer));
    let (server, address) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            resolutions.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(address) })
        })
    };
    let peer = RemoteSessionConsensusPeer::new_with_resolver(
        binding.clone(),
        resolver,
        client_tls.clone(),
        None,
    );
    let request = |family, payload: &[u8]| {
        SessionConsensusWireRequest::try_new(
            binding.consensus_identity(),
            binding.local_consensus_node_id(),
            family,
            payload.to_vec(),
        )
        .unwrap()
    };
    let parent_started = tokio::time::Instant::now();
    let parent_deadline = parent_started + opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT;
    let first = tokio::spawn({
        let peer = peer.clone();
        let request = request(SessionConsensusRpcFamily::AppendEntries, b"held-response");
        async move { peer.call(request).await }
    });
    tokio::time::timeout_at(parent_deadline, handler.entered.notified())
        .await
        .expect("accepted authenticated RPC reached the handler");
    let accepted = accepted_rx.await.unwrap();
    let executions = observer.executions.get().unwrap();
    assert_eq!(executions.available_permits(), execution_limit - 1);
    assert_eq!(
        peer.connection_pool.primary.in_flight.available_permits(),
        0
    );
    assert_eq!(
        peer.connection_pool.overflow.in_flight.available_permits(),
        1
    );

    // Advance the existing RPC timer only after real TCP/TLS admission, then
    // resume real time before waiting for socket I/O. The original parent
    // deadline includes both this elapsed interval and subsequent recovery.
    tokio::time::pause();
    tokio::time::advance(
        DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(SessionConsensusRpcFamily::AppendEntries),
    )
    .await;
    tokio::time::resume();
    assert_eq!(
        first.await.unwrap(),
        Err(SessionConsensusPeerError::Timeout)
    );
    assert!(peer
        .connection_pool
        .primary
        .connection
        .lock()
        .await
        .is_none());
    assert_eq!(
        peer.connection_pool.primary.in_flight.available_permits(),
        1
    );
    assert_eq!(
        executions.available_permits(),
        execution_limit - 1,
        "caller timeout must not cancel admitted handler work"
    );
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout_at(parent_deadline, accepted.peek(&mut byte))
            .await
            .expect("closed client reaches server")
            .unwrap(),
        0
    );
    drop(accepted);
    handler.release.add_permits(1);
    let terminal = tokio::time::timeout_at(parent_deadline, terminals.recv())
        .await
        .expect("late response write terminates")
        .unwrap();
    assert!(
        matches!(&terminal, Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe),
        "accepted RPC must reach a real rpc-write/BrokenPipe, got {terminal:?}"
    );
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
    assert_eq!(executions.available_permits(), execution_limit);
    assert_connection_counters(2, 1, 1);

    // No renewed parent budget and no backoff sleep in the test: recovery must
    // do its own admission inside precisely the original remaining interval.
    let remaining = parent_deadline.duration_since(tokio::time::Instant::now());
    assert!(remaining < opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT);
    let response = tokio::time::timeout_at(
        parent_deadline,
        peer.call_with_timeout(
            request(SessionConsensusRpcFamily::ReadBarrier, b"head"),
            remaining,
        ),
    )
    .await
    .expect("head recovery stays in original parent budget");
    assert_eq!(
        response,
        Ok(SessionConsensusWireResponse {
            result: Ok(80_u64.to_be_bytes().to_vec())
        })
    );
    assert!(tokio::time::Instant::now() < parent_deadline);
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        2,
        "exactly one replacement connection"
    );
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        2,
        "no replay of the expired RPC"
    );
    assert_eq!(
        peer.connection_pool.primary.in_flight.available_permits(),
        1
    );
    assert_eq!(
        peer.connection_pool.overflow.in_flight.available_permits(),
        1
    );
    assert!(peer
        .connection_pool
        .primary
        .connection
        .lock()
        .await
        .is_some());
    assert!(peer
        .connection_pool
        .overflow
        .connection
        .lock()
        .await
        .is_none());
    assert_eq!(executions.available_permits(), execution_limit);
    assert_connection_counters(4, 2, 1);
    assert_eq!(server_tls.material_status().epoch(), server_epoch);
    assert_eq!(client_tls.material_status().epoch(), client_epoch);
    assert_eq!(
        server_tls.material_status().availability(),
        opc_tls::TlsMaterialAvailability::Ready
    );
    assert_eq!(
        client_tls.material_status().availability(),
        opc_tls::TlsMaterialAvailability::Ready
    );
    eprintln!(
        "late-write recovery: real rpc-write/BrokenPipe; head=80; resolutions=2; parent_remaining={:?}",
        parent_deadline.duration_since(tokio::time::Instant::now())
    );

    // End the recovered connection normally before stopping the listener, so
    // terminal accounting cannot be hidden by intentional task abortion.
    drop(peer);
    assert!(tokio::time::timeout_at(parent_deadline, terminals.recv())
        .await
        .unwrap()
        .unwrap()
        .is_ok());
    server.abort_and_wait().await;
    assert_eq!(
        observer.connections.get().unwrap().available_permits(),
        execution_limit
    );
    assert_eq!(executions.available_permits(), execution_limit);
    assert_connection_counters(4, 3, 1);
    assert_eq!(
        METRICS
            .session_net_lifecycle_active_connections
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        METRICS
            .session_net_lifecycle_draining_connections
            .load(Ordering::Relaxed),
        0
    );
    drop(client_source);
}
