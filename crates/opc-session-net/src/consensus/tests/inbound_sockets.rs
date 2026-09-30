//! Physical endpoint detectors use real TCP and the existing mTLS fixture.
//! Counts do not qualify TLS allocation bytes or aggregate memory bounds.

use super::*;
use capacity_observation::{ConsensusBufferObservation, InboundSocketPhase};

async fn accepted_before_setup(armed: bool) {
    let (server_binding, _) = bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let hook = ConsensusAcceptedSetupHook::new();
    let mut server = SessionConsensusServer::new_insecure(
        Arc::new(CountingHandler(AtomicUsize::new(0))),
        server_binding,
    );
    server.post_accept_setup_hook = Some(Arc::clone(&hook));
    let listen = server.listen("127.0.0.1:0".parse().expect("loopback address"));
    let (handle, address) = if armed {
        observation.scope_inbound_sockets(listen).await
    } else {
        listen.await
    }
    .expect("listen with original limits and deadlines");
    let guard =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let mut clients = Vec::new();
    let mut samples = Vec::new();
    for _ in 0..2 {
        clients.push(
            tokio::time::timeout_at(guard, TcpStream::connect(address))
                .await
                .expect("connect guard")
                .expect("real TCP connect"),
        );
        tokio::time::timeout_at(guard, hook.entered.notified())
            .await
            .expect("existing child setup rendezvous");
        samples.push(observation.inbound_socket_snapshot());
    }
    // Both real accepted owners are held before the connection handler starts.
    // Cancelling the tasks must destroy captured sockets even if setup never ran.
    // The current-thread test does not yield between abort and this snapshot:
    // cancellation has been requested but the captured sockets still exist.
    handle.abort();
    let cancelled = observation.inbound_socket_snapshot();
    handle.abort_and_wait().await;
    for mut client in clients {
        let mut byte = [0_u8];
        assert_eq!(
            tokio::time::timeout_at(guard, client.read(&mut byte))
                .await
                .expect("peer closure guard")
                .expect("peer closure"),
            0
        );
    }
    let drained = observation.inbound_socket_snapshot();
    assert!(drained.owners.is_empty());
    assert!(!drained.registration_exhausted);
    assert_eq!(
        cancelled, samples[1],
        "abort request is not a physical drop"
    );
    println!(
        "CONFIG_CAPACITY_INBOUND_SOCKET_ACCEPT_LIFECYCLE armed={armed} real_endpoints=2 observed_first={} observed_second={} joined=true peer_eof=true drained=true tls_bytes_qualified=false",
        samples[0].owners.len(),
        samples[1].owners.len(),
    );
    if armed {
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.owners.len())
                .collect::<Vec<_>>(),
            vec![1, 2],
            "CONFIG_CAPACITY_INBOUND_SOCKET_OMISSION_RED: real accepted sockets were absent before setup"
        );
        assert_eq!(samples[0].owners[0], samples[1].owners[0]);
        assert_ne!(
            samples[1].owners[0].socket_id,
            samples[1].owners[1].socket_id
        );
        assert!(samples[1]
            .owners
            .iter()
            .all(|owner| owner.phase == InboundSocketPhase::Accepted));
    } else {
        assert!(samples.iter().all(|sample| sample.owners.is_empty()));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_sockets_remain_observed_before_setup_until_abort_joins() {
    accepted_before_setup(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn feature_alone_does_not_enroll_a_listener() {
    accepted_before_setup(false).await;
}

#[tokio::test]
async fn one_socket_registration_survives_until_the_last_split_half_drops() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let guard =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let (client, accepted) = tokio::time::timeout_at(guard, async {
        tokio::join!(TcpStream::connect(address), listener.accept())
    })
    .await
    .expect("real TCP pair guard");
    let mut client = client.expect("client socket");
    let (stream, _) = accepted.expect("accepted socket");
    let socket = capacity_observation::InboundSocket::new(stream, Some(&observation));
    let numeric_context = socket.context();
    let original = observation.inbound_socket_snapshot();
    let (mut reader, mut writer) = tokio::io::split(socket);
    let mut byte = [0_u8];
    tokio::time::timeout_at(guard, async {
        client.write_all(&[7]).await.expect("client write");
        reader.read_exact(&mut byte).await.expect("accepted read");
    })
    .await
    .expect("real read guard");
    assert_eq!(byte, [7]);
    drop(reader);
    let one_half = observation.inbound_socket_snapshot();
    tokio::time::timeout_at(guard, async {
        writer.write_all(&[9]).await.expect("surviving half write");
        client.read_exact(&mut byte).await.expect("client read");
    })
    .await
    .expect("real surviving-half IO guard");
    assert_eq!(byte, [9]);
    drop(writer);
    assert_eq!(
        tokio::time::timeout_at(guard, client.read(&mut byte))
            .await
            .expect("last-half closure guard")
            .expect("last-half closure"),
        0
    );
    assert_eq!(original.owners.len(), 1);
    assert_eq!(original, one_half, "split halves share one real TCP owner");
    assert!(observation.inbound_socket_snapshot().owners.is_empty());
    drop(numeric_context);
}

#[derive(Debug)]
pub(super) struct HeldSocketHandler {
    pub(super) entered: tokio::sync::mpsc::Sender<()>,
    pub(super) release: Semaphore,
}

#[async_trait]
impl SessionConsensusRpcHandler for HeldSocketHandler {
    async fn handle(
        &self,
        _authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.entered.try_send(()).expect("two admitted test calls");
        self.release
            .acquire()
            .await
            .expect("test release remains open")
            .forget();
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

pub(super) fn material_fixture_bindings() -> (LocalReplicaBinding, RemoteReplicaBinding) {
    // The shared certificate fixture's trust bundle uses test-domain.
    let members = (1..=2)
        .map(|index| {
            QuorumReplicaDescriptor::new(
                ReplicaId::new(format!("replica-{index}")).expect("replica"),
                ReplicaEndpoint::new(format!("replica-{index}.invalid"), 7443).expect("endpoint"),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
                ))
                .expect("fixture TLS identity"),
                ReplicaFailureDomain::new(format!("zone-{index}")).expect("failure domain"),
                ReplicaBackingIdentity::new(format!("disk-{index}")).expect("backing"),
            )
        })
        .collect();
    let manifest = Arc::new(
        SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("physical-inbound-sockets").expect("cluster"),
            SessionConfigurationGeneration::new("legacy").expect("generation"),
            SessionConfigurationEpoch::new(1).expect("epoch"),
            members,
        )
        .expect("fixture manifest"),
    );
    let server = manifest
        .bind_local(ReplicaId::new("replica-2").expect("server ID"))
        .expect("server binding");
    let client = manifest
        .bind_local(ReplicaId::new("replica-1").expect("client ID"))
        .expect("client binding")
        .bind_remote(ReplicaId::new("replica-2").expect("server ID"))
        .expect("remote server binding");
    (server, client)
}

async fn negotiated_sockets(tls: bool) {
    let (server_binding, client_binding) = material_fixture_bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(2);
    let handler = Arc::new(HeldSocketHandler {
        entered: entered_tx,
        release: Semaphore::new(0),
    });
    let material = crate::test_support::RotatableServerMaterial::new(
        client_binding.remote_spiffe_id().as_str(),
    );
    let client_spiffe = server_binding
        .bind_remote(client_binding.local_replica_id().clone())
        .expect("reverse member binding")
        .remote_spiffe_id()
        .clone();
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        tls.then(|| material.config()),
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let (handle, address) = observation
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("listen with original setup and connection limits");
    let peer = RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::pinned(address),
        tls.then(|| material.trusted_client_config(client_spiffe.as_str())),
        client_binding.clone(),
        None,
    );
    let mut calls = Vec::new();
    let mut samples = Vec::new();
    // This is a harness guard only. Peers retain their original profiled
    // complete-call and 1,500 ms cold-setup deadlines without an override.
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    for marker in [17_u8, 29] {
        let caller = peer.clone();
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::ForwardMutation,
            vec![marker],
        )
        .expect("synthetic bounded call");
        calls.push(tokio::spawn(async move { caller.call(request).await }));
        tokio::time::timeout_at(guard, entered_rx.recv())
            .await
            .expect("real handler rendezvous guard")
            .expect("real handler entered");
        samples.push(observation.inbound_socket_snapshot());
    }
    // Each handler holds a genuine request on a different live pool lane.
    // The snapshot is taken at this real rendezvous, never reconstructed from peaks.
    handler.release.add_permits(2);
    for (call, marker) in calls.into_iter().zip([17_u8, 29]) {
        let response = tokio::time::timeout_at(guard, call)
            .await
            .expect("call completion guard")
            .expect("call task joined")
            .expect("real negotiated call succeeded");
        assert_eq!(response.result, Ok(vec![marker]));
    }
    let cached = observation.inbound_socket_snapshot();
    drop(peer);
    tokio::time::timeout_at(guard, observation.wait_for_no_inbound_sockets())
        .await
        .expect("cached client drop reaches server EOF and socket destruction");
    handle.abort_and_drain_handlers_for_test().await;
    let drained = observation.inbound_socket_snapshot();
    assert!(drained.owners.is_empty());
    assert!(!drained.registration_exhausted);
    println!(
        "CONFIG_CAPACITY_INBOUND_SOCKET_NEGOTIATED_LIFECYCLE tls={tls} simultaneous_endpoints=2 observed_first={} observed_second={} real_replies=true joined=true drained=true tls_bytes_qualified=false",
        samples[0].owners.len(),
        samples[1].owners.len(),
    );
    assert_eq!(
        samples
            .iter()
            .map(|sample| sample.owners.len())
            .collect::<Vec<_>>(),
        vec![1, 2],
        "CONFIG_CAPACITY_INBOUND_SOCKET_EARLY_RELEASE_RED: real negotiated endpoints were absent at the handler rendezvous"
    );
    assert_eq!(samples[0].owners[0], samples[1].owners[0]);
    assert_ne!(
        samples[1].owners[0].socket_id,
        samples[1].owners[1].socket_id
    );
    assert!(samples[1]
        .owners
        .iter()
        .all(|owner| owner.phase == InboundSocketPhase::Negotiated));
    assert_eq!(
        samples[1], cached,
        "correlated replies preserve the two cached endpoints"
    );
}

#[tokio::test]
async fn plaintext_negotiated_sockets_keep_identity_through_two_shared_pool_lanes() {
    negotiated_sockets(false).await;
}

#[tokio::test]
async fn mtls_negotiated_sockets_keep_identity_through_two_shared_pool_lanes() {
    negotiated_sockets(true).await;
}

#[tokio::test]
async fn rejected_bootstrap_closes_its_observed_socket_without_handler_admission() {
    let (server_binding, client_binding) = bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let hook = ConsensusAcceptedSetupHook::new();
    let mut server = SessionConsensusServer::new_insecure(handler.clone(), server_binding);
    server.post_accept_setup_hook = Some(Arc::clone(&hook));
    let (handle, address) = observation
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("listen");
    let guard =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let mut client = TcpStream::connect(address).await.expect("real TCP connect");
    tokio::time::timeout_at(guard, hook.entered.notified())
        .await
        .expect("accepted socket rendezvous");
    let accepted = observation.inbound_socket_snapshot();
    hook.release.notify_one();
    let rejected = tokio::time::timeout_at(guard, async {
        write_frame(
            &mut client,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION + 1,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: client_binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: client_binding.remote_replica_id().as_str().to_owned(),
                identity: client_binding.consensus_identity(),
                sender_node_id: client_binding.local_consensus_node_id(),
                expected_server_node_id: client_binding.remote_consensus_node_id(),
                handshake_nonce: uuid::Uuid::new_v4(),
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("write typed refused Hello");
        read_frame::<_, SessionConsensusBootstrapResponse>(&mut client, MAX_HANDSHAKE_FRAME_SIZE)
            .await
            .expect("read actual refusal")
    })
    .await
    .expect("original setup guard contains refusal");
    let mut byte = [0_u8];
    let eof = tokio::time::timeout_at(guard, client.read(&mut byte))
        .await
        .expect("refusal socket closure guard")
        .expect("refusal socket closure");
    handle.abort_and_wait().await;
    assert_eq!(eof, 0);
    assert!(matches!(
        rejected,
        SessionConsensusBootstrapResponse::Rejected(_)
    ));
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    assert!(observation.inbound_socket_snapshot().owners.is_empty());
    assert_eq!(
        accepted.owners.len(),
        1,
        "CONFIG_CAPACITY_INBOUND_SOCKET_OMISSION_RED: refused endpoint was absent before bootstrap"
    );
}
