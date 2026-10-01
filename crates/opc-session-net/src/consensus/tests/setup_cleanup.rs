//! Superseded setup drops its real socket before terminal publication waits.
//!
//! Plaintext sockets isolate the ownership boundary. They do not measure TLS
//! allocation capacity or establish aggregate transport memory bounds.

use super::*;

async fn superseded_setup_cleanup(accepted: bool) {
    let (server_binding, client_binding) = bindings();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind controlled bootstrap peer");
    let peer = RemoteSessionConsensusPeer::new_insecure(
        client_binding,
        listener.local_addr().expect("listener address"),
        None,
    );
    let connector = peer.cold_connector();
    let epoch = connector.epoch();
    let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
    let reconnect_gate = Arc::clone(&peer.connection_pool.reconnect_gate);
    let attempt_id = uuid::Uuid::new_v4();
    let attempt_deadline =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let receipt = Arc::new(ConsensusColdAttemptReceipt::default());
    coordinator.state.lock().await.phase = ConsensusColdConnectionPhase::Connecting {
        attempt_id,
        epoch,
        attempt_deadline,
        receipt: Arc::clone(&receipt),
        remote_retirement_probe: false,
    };
    let hook = ConsensusPostAcceptedBootstrapHook::new();
    let attempt = {
        let hook = Arc::clone(&hook);
        let coordinator = Arc::clone(&coordinator);
        let reconnect_gate = Arc::clone(&reconnect_gate);
        let shutdown = peer.connection_pool.shutdown.subscribe();
        tokio::spawn(async move {
            CONSENSUS_POST_ACCEPTED_BOOTSTRAP_HOOK
                .scope(
                    hook,
                    run_detached_consensus_connection_attempt(
                        connector,
                        coordinator,
                        reconnect_gate,
                        shutdown,
                        attempt_id,
                        epoch,
                        attempt_deadline,
                    ),
                )
                .await;
        })
    };
    let (mut remote, _) = tokio::time::timeout_at(attempt_deadline, listener.accept())
        .await
        .expect("original setup budget contains TCP accept")
        .expect("accept actual setup socket");
    let request: SessionConsensusBootstrapRequest = tokio::time::timeout_at(
        attempt_deadline,
        read_frame(&mut remote, MAX_HANDSHAKE_FRAME_SIZE),
    )
    .await
    .expect("original setup budget contains Hello")
    .expect("read real Hello");
    if accepted {
        let SessionConsensusBootstrapRequest::Hello(hello) = request;
        tokio::time::timeout_at(
            attempt_deadline,
            write_frame(
                &mut remote,
                &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                    transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                    contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                    identity: hello.identity,
                    server_node_id: server_binding.local_consensus_node_id(),
                    accepted_sender_node_id: hello.sender_node_id,
                    handshake_nonce: hello.handshake_nonce,
                    accepted_response_frame_size: hello.requested_response_frame_size,
                    server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                }),
            ),
        )
        .await
        .expect("original setup budget contains Accepted")
        .expect("write valid Accepted");
        tokio::time::timeout_at(attempt_deadline, hook.entered.notified())
            .await
            .expect("setup validated the real Accepted");
    }

    // Keep the old Connecting slot locked. Physical cleanup must precede
    // both the reconnect permit release and the blocked terminal publication.
    let state = coordinator.state.lock().await;
    peer.reauthentication
        .request_reauthentication()
        .expect("supersede setup");
    let successor_epoch = peer.cold_connector().epoch();
    hook.release.notify_one();
    let admission = reconnect_gate
        .acquire_classified(
            attempt_deadline,
            successor_epoch.reauthentication_generation,
            successor_epoch.material_epoch,
        )
        .await;
    let mut byte = [0_u8; 1];
    let closed_before_publication =
        tokio::time::timeout_at(attempt_deadline, remote.read(&mut byte)).await;

    // Join before asserting, including the deliberately failing controls.
    drop(state);
    let acquired = match admission {
        ReconnectAdmission::Admitted(replacement) => {
            replacement.established();
            true
        }
        _ => false,
    };
    attempt.await.expect("terminal publication completed");
    assert_eq!(
        receipt.terminal(),
        Some(SessionConsensusPeerError::Unavailable)
    );
    println!("CONFIG_CAPACITY_SETUP_CLEANUP_LIFECYCLE accepted={accepted} original_hello=true superseded=true joined=true successor_admitted={acquired} full_memory_bound=false");
    assert!(acquired, "successor acquired the original reconnect permit");
    assert!(
        matches!(closed_before_publication, Ok(Ok(0))),
        "CONFIG_CAPACITY_SETUP_PHYSICAL_DROP_RED: superseded setup retained its socket after reconnect admission released"
    );
}

#[tokio::test]
async fn pending_setup_releases_socket_before_terminal_publication() {
    superseded_setup_cleanup(false).await;
}

#[tokio::test]
async fn accepted_setup_releases_socket_before_terminal_publication() {
    superseded_setup_cleanup(true).await;
}
