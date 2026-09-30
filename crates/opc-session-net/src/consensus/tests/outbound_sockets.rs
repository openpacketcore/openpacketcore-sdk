//! Real outbound lifetime detectors. Observer assertions follow socket cleanup
//! and joins; controls must fail their sentinel, not an I/O or harness guard.

use std::future::Future;

use super::inbound_sockets::{material_fixture_bindings, HeldSocketHandler};
use super::*;
use capacity_observation::{ConsensusBufferObservation, OutboundAttemptPhase, OutboundSocketPhase};

type AttemptTask = tokio::task::JoinHandle<()>;
type AttemptSender = tokio::sync::mpsc::UnboundedSender<AttemptTask>;

tokio::task_local! { static ATTEMPT_TASKS: AttemptSender; }

// This fixture only captures the actual existing spawn's handle. Dropping a
// handle outside this explicit test scope retains the original detached task.
pub(in crate::consensus) fn capture_spawned_attempt(task: AttemptTask) {
    let _ = ATTEMPT_TASKS.try_with(|sender| {
        let _ = sender.send(task);
    });
}

fn request(binding: &RemoteReplicaBinding, marker: u8) -> SessionConsensusWireRequest {
    SessionConsensusWireRequest::try_new(
        binding.consensus_identity(),
        binding.local_consensus_node_id(),
        SessionConsensusRpcFamily::ForwardMutation,
        vec![marker],
    )
    .expect("bounded synthetic request")
}

fn spawn_call(
    peer: RemoteSessionConsensusPeer,
    request: SessionConsensusWireRequest,
    sender: &AttemptSender,
) -> tokio::task::JoinHandle<Result<SessionConsensusWireResponse, SessionConsensusPeerError>> {
    let sender = sender.clone();
    tokio::spawn(async move { ATTEMPT_TASKS.scope(sender, peer.call(request)).await })
}

#[tokio::test]
async fn shared_pending_setup_survives_caller_cancellation_until_terminal_join() {
    let (_, binding) = bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind raw peer");
    let peer = RemoteSessionConsensusPeer::new_insecure(
        binding.clone(),
        listener.local_addr().expect("address"),
        None,
    )
    .with_buffer_observation(Arc::clone(&observation));
    let (tasks_tx, mut tasks_rx) = tokio::sync::mpsc::unbounded_channel();
    let guard =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let first = spawn_call(peer.clone(), request(&binding, 11), &tasks_tx);
    let (mut remote, _) = tokio::time::timeout_at(guard, listener.accept())
        .await
        .expect("original setup contains accept")
        .expect("real accepted TCP");
    let hello: SessionConsensusBootstrapRequest =
        tokio::time::timeout_at(guard, read_frame(&mut remote, MAX_HANDSHAKE_FRAME_SIZE))
            .await
            .expect("original setup contains Hello")
            .expect("real Hello");
    let attempt = tokio::time::timeout_at(guard, tasks_rx.recv())
        .await
        .expect("spawn capture guard")
        .expect("actual shared setup handle");
    // Poll the second actual call once while the first setup awaits Accepted.
    // Its lane/cold acquisition parks on the same real Connecting coordinator.
    let mut second = Box::pin(peer.call(request(&binding, 13)));
    let second_pending =
        std::future::poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx).is_pending())).await;
    let pending_calls = observation.pending_snapshot();
    let shared = observation.outbound_socket_snapshot();
    let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
    let shared_receipt_holders = match &coordinator.state.lock().await.phase {
        ConsensusColdConnectionPhase::Connecting { receipt, .. } => Arc::strong_count(receipt),
        _ => 0,
    };
    first.abort();
    let first_cancelled = first.await.is_err_and(|error| error.is_cancelled());
    drop(second);
    let cancelled = observation.outbound_socket_snapshot();
    let callers_drained = observation.pending_snapshot().owners.is_empty();

    // Lock terminal publication, supersede, and independently reacquire the
    // existing reconnect permit. The previously fixed cleanup must yield EOF
    // before this lock is released, while the detached future still exists.
    let state = coordinator.state.lock().await;
    let cancelled_receipt_holders = match &state.phase {
        ConsensusColdConnectionPhase::Connecting { receipt, .. } => Arc::strong_count(receipt),
        _ => 0,
    };
    peer.reauthentication
        .request_reauthentication()
        .expect("supersede");
    let epoch = peer.cold_connector().epoch();
    let admission = peer
        .connection_pool
        .reconnect_gate
        .acquire_classified(
            guard,
            epoch.reauthentication_generation,
            epoch.material_epoch,
        )
        .await;
    let mut byte = [0_u8];
    let eof = tokio::time::timeout_at(guard, remote.read(&mut byte)).await;
    let terminal = observation.outbound_socket_snapshot();
    drop(state);
    let admitted = match admission {
        ReconnectAdmission::Admitted(replacement) => {
            replacement.established();
            true
        }
        _ => false,
    };
    tokio::time::timeout_at(guard, attempt)
        .await
        .expect("setup join guard")
        .expect("actual detached attempt joined");
    let no_extra_attempt = tasks_rx.try_recv().is_err();
    drop(peer);
    drop(remote);
    drop(listener);
    let drained = observation.outbound_socket_snapshot();
    assert!(matches!(hello, SessionConsensusBootstrapRequest::Hello(_)));
    assert!(second_pending && first_cancelled && callers_drained && admitted);
    assert_eq!(
        pending_calls.owners.len(),
        2,
        "two real cold acquisition callers"
    );
    assert!(pending_calls.owners.iter().all(|owner| {
        owner.phase == capacity_observation::PendingRpcPhase::ColdConnectionAcquire
    }));
    assert_eq!(
        shared_receipt_holders, 3,
        "coordinator and two actual joined callers"
    );
    assert_eq!(
        cancelled_receipt_holders, 1,
        "only the coordinator retains the receipt"
    );
    assert!(
        matches!(eof, Ok(Ok(0))),
        "real EOF precedes terminal publication"
    );
    assert!(
        no_extra_attempt,
        "joined callers did not spawn separate setups"
    );
    assert!(drained.attempts.is_empty() && drained.sockets.is_empty());
    assert!(!drained.registration_exhausted);
    println!("CONFIG_CAPACITY_OUTBOUND_PENDING_LIFECYCLE callers=2 callers_cancelled=true real_hello=true peer_eof=true setup_joined=true drained=true");
    assert_eq!(
        shared.attempts.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_ATTEMPT_OMISSION_RED"
    );
    assert_eq!(
        shared.sockets.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_OMISSION_RED"
    );
    assert_eq!(
        shared, cancelled,
        "caller cancellation cannot own detached registration"
    );
    assert_eq!(shared.attempts[0].phase, OutboundAttemptPhase::Bootstrap);
    assert_eq!(shared.sockets[0].phase, OutboundSocketPhase::Bootstrap);
    assert_eq!(shared.attempts[0].attempt_id, shared.sockets[0].attempt_id);
    assert_eq!(shared.attempts[0].source, binding.local_consensus_node_id());
    assert_eq!(
        shared.attempts[0].target,
        binding.remote_consensus_node_id()
    );
    assert_eq!(
        terminal.attempts.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_ATTEMPT_TERMINAL_RED"
    );
    assert_eq!(
        terminal.attempts[0].attempt_id,
        shared.attempts[0].attempt_id
    );
    assert_eq!(terminal.attempts[0].phase, OutboundAttemptPhase::Publishing);
    assert!(
        terminal.sockets.is_empty(),
        "TCP destruction is earlier than detached finish"
    );
}

async fn wait_for_ready(
    coordinator: &ConsensusColdConnectionCoordinator,
    guard: tokio::time::Instant,
) {
    tokio::time::timeout_at(guard, async {
        loop {
            let changed = coordinator.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if matches!(
                coordinator.state.lock().await.phase,
                ConsensusColdConnectionPhase::Ready { .. }
            ) {
                return;
            }
            changed.await;
        }
    })
    .await
    .expect("real Ready publication within the original setup budget");
}

async fn ready_cached_lanes(tls: bool) {
    let (server_binding, binding) = material_fixture_bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(3);
    let handler = Arc::new(HeldSocketHandler {
        entered: entered_tx,
        release: Semaphore::new(0),
    });
    let material =
        crate::test_support::RotatableServerMaterial::new(binding.remote_spiffe_id().as_str());
    let client_spiffe = server_binding
        .bind_remote(binding.local_replica_id().clone())
        .expect("reverse binding")
        .remote_spiffe_id()
        .clone();
    let hook = ConsensusAcceptedSetupHook::new();
    let mut server = SessionConsensusServer::from_transport(
        handler.clone(),
        tls.then(|| material.config()),
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    server.post_accept_setup_hook = Some(Arc::clone(&hook));
    let (handle, address) = observation
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("listen with original limits");
    let peer = RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::pinned(address),
        tls.then(|| material.trusted_client_config(client_spiffe.as_str())),
        binding.clone(),
        None,
    )
    .with_buffer_observation(Arc::clone(&observation));
    let coordinator = Arc::clone(&peer.connection_pool.cold_connection);
    let (tasks_tx, mut tasks_rx) = tokio::sync::mpsc::unbounded_channel();
    // Harness guard only; every physical setup retains its original 1,500 ms
    // bound, and every caller/server uses the unchanged timing profile.
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let seed = spawn_call(peer.clone(), request(&binding, 5), &tasks_tx);
    tokio::time::timeout_at(guard, hook.entered.notified())
        .await
        .expect("real accepted TCP");
    let seed_attempt = tokio::time::timeout_at(guard, tasks_rx.recv())
        .await
        .expect("spawn capture guard")
        .expect("real seed attempt");
    seed.abort();
    let seed_cancelled = seed.await.is_err_and(|error| error.is_cancelled());
    hook.release.notify_one();
    wait_for_ready(&coordinator, guard).await;
    let ready = observation.outbound_socket_snapshot();

    let first = spawn_call(peer.clone(), request(&binding, 17), &tasks_tx);
    tokio::time::timeout_at(guard, entered_rx.recv())
        .await
        .expect("first handler guard")
        .expect("first real request");
    tokio::time::timeout_at(guard, seed_attempt)
        .await
        .expect("seed setup join guard")
        .expect("claimed Ready ends actual seed setup task");
    let first_active = observation.outbound_socket_snapshot();

    let second = spawn_call(peer.clone(), request(&binding, 29), &tasks_tx);
    tokio::time::timeout_at(guard, hook.entered.notified())
        .await
        .expect("second real TCP");
    let second_attempt = tokio::time::timeout_at(guard, tasks_rx.recv())
        .await
        .expect("spawn capture guard")
        .expect("second lane's actual setup");
    hook.release.notify_one();
    tokio::time::timeout_at(guard, entered_rx.recv())
        .await
        .expect("second handler guard")
        .expect("second real request");
    tokio::time::timeout_at(guard, second_attempt)
        .await
        .expect("second setup join guard")
        .expect("second setup actually joined");
    let both_active = observation.outbound_socket_snapshot();
    let inbound_pair = observation.inbound_socket_snapshot();
    handler.release.add_permits(2);
    let mut replies = Vec::new();
    for call in [first, second] {
        replies.push(
            tokio::time::timeout_at(guard, call)
                .await
                .expect("reply guard")
                .expect("caller joined")
                .expect("authenticated negotiated reply")
                .result,
        );
    }
    let cached = observation.outbound_socket_snapshot();
    let reused_call = spawn_call(peer.clone(), request(&binding, 43), &tasks_tx);
    tokio::time::timeout_at(guard, entered_rx.recv())
        .await
        .expect("reused handler guard")
        .expect("cached lane real request");
    handler.release.add_permits(1);
    let reused_reply = tokio::time::timeout_at(guard, reused_call)
        .await
        .expect("reuse guard")
        .expect("reuse caller joined")
        .expect("reused correlated reply");
    let reused = observation.outbound_socket_snapshot();
    let no_extra_attempt = tasks_rx.try_recv().is_err();
    drop(peer);
    tokio::time::timeout_at(guard, observation.wait_for_no_inbound_sockets())
        .await
        .expect("server observes cached client closures before server abort");
    handle.abort_and_drain_handlers_for_test().await;
    let drained = observation.outbound_socket_snapshot();
    assert!(seed_cancelled && no_extra_attempt);
    assert_eq!(replies, vec![Ok(vec![17]), Ok(vec![29])]);
    assert_eq!(reused_reply.result, Ok(vec![43]));
    assert_eq!(
        inbound_pair.owners.len(),
        2,
        "two real server endpoint owners"
    );
    assert!(drained.attempts.is_empty() && drained.sockets.is_empty());
    assert!(!drained.registration_exhausted);
    println!("CONFIG_CAPACITY_OUTBOUND_LANES_LIFECYCLE tls={tls} retained_ready=true actual_setup_joins=2 correlated_replies=3 server_drained_before_abort=true drained=true");
    assert_eq!(
        ready.sockets.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_READY_RED"
    );
    assert_eq!(ready.sockets[0].phase, OutboundSocketPhase::Ready);
    assert_eq!(
        ready.attempts.len(),
        1,
        "Ready monitor remains a live detached future"
    );
    assert_eq!(
        first_active.sockets.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_ACTIVE_RED"
    );
    assert!(
        first_active.attempts.is_empty(),
        "setup join does not remove its TCP row"
    );
    assert_eq!(
        first_active.sockets[0].socket_id,
        ready.sockets[0].socket_id
    );
    assert_eq!(first_active.sockets[0].phase, OutboundSocketPhase::Active);
    assert_eq!(
        both_active.sockets.len(),
        2,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_ACTIVE_RED"
    );
    assert!(both_active.attempts.is_empty());
    assert_ne!(
        both_active.sockets[0].socket_id,
        both_active.sockets[1].socket_id
    );
    assert_ne!(
        both_active.sockets[0].attempt_id,
        both_active.sockets[1].attempt_id
    );
    assert!(both_active.sockets.iter().all(|owner| {
        owner.source == binding.local_consensus_node_id()
            && owner.target == binding.remote_consensus_node_id()
            && owner.phase == OutboundSocketPhase::Active
    }));
    assert_eq!(
        cached.sockets.len(),
        2,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_CACHED_RED"
    );
    for (active, cached) in both_active.sockets.iter().zip(&cached.sockets) {
        assert_eq!(active.socket_id, cached.socket_id);
        assert_eq!(active.attempt_id, cached.attempt_id);
        assert_eq!(cached.phase, OutboundSocketPhase::Cached);
    }
    assert_eq!(
        cached, reused,
        "cache reuse preserves both independent identities"
    );
}

#[tokio::test]
async fn plaintext_ready_connection_keeps_identity_through_two_cached_lanes() {
    ready_cached_lanes(false).await;
}

#[tokio::test]
async fn mtls_ready_connection_keeps_identity_through_two_cached_lanes() {
    ready_cached_lanes(true).await;
}

#[tokio::test]
async fn last_outbound_split_half_owns_tcp_after_its_attempt_joins() {
    let (_, binding) = bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let guard =
        tokio::time::Instant::now() + DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout();
    let task = tokio::spawn(capacity_observation::observe_outbound_attempt(
        Some(&observation),
        binding.local_consensus_node_id(),
        binding.remote_consensus_node_id(),
        async move {
            let tcp = TcpStream::connect(address)
                .await
                .expect("original real connect");
            let socket = capacity_observation::OutboundSocket::new(tcp);
            let context = socket.context();
            let (reader, writer) = tokio::io::split(socket);
            (reader, writer, context)
        },
    ));
    let (mut remote, _) = tokio::time::timeout_at(guard, listener.accept())
        .await
        .expect("accept guard")
        .expect("real TCP accepted");
    let (mut reader, mut writer, context) = tokio::time::timeout_at(guard, task)
        .await
        .expect("owned future join guard")
        .expect("actual attempt future joined");
    let connected = observation.outbound_socket_snapshot();
    let mut byte = [0_u8];
    tokio::time::timeout_at(guard, async {
        remote.write_all(&[7]).await.expect("real remote write");
        reader
            .read_exact(&mut byte)
            .await
            .expect("actual outbound read");
    })
    .await
    .expect("read guard");
    let first_byte = byte;
    drop(reader);
    let last_half = observation.outbound_socket_snapshot();
    let mut drain = Box::pin(observation.wait_for_no_outbound_owners());
    let drain_was_pending =
        std::future::poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await;
    tokio::time::timeout_at(guard, async {
        writer
            .write_all(&[9])
            .await
            .expect("actual surviving write half");
        remote
            .read_exact(&mut byte)
            .await
            .expect("real remote read");
    })
    .await
    .expect("surviving-half I/O guard");
    let second_byte = byte;
    drop(writer);
    let eof = tokio::time::timeout_at(guard, remote.read(&mut byte)).await;
    if drain_was_pending {
        tokio::time::timeout_at(guard, drain)
            .await
            .expect("last owner wakes the drain waiter");
    }
    let drained_with_context = observation.outbound_socket_snapshot();
    drop(context);
    drop(remote);
    drop(listener);
    assert_eq!(first_byte, [7]);
    assert_eq!(second_byte, [9]);
    assert!(matches!(eof, Ok(Ok(0))), "real last-half EOF");
    assert!(connected.attempts.is_empty() && last_half.attempts.is_empty());
    assert!(drained_with_context.sockets.is_empty());
    assert!(!drained_with_context.registration_exhausted);
    println!("CONFIG_CAPACITY_OUTBOUND_SPLIT_LIFECYCLE setup_joined=true bidirectional_bytes=true peer_eof=true numeric_context_retained_after_tcp_drop=true drained=true");
    assert_eq!(
        connected.sockets.len(),
        1,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_OMISSION_RED"
    );
    assert_eq!(
        connected, last_half,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_LAST_HALF_RED"
    );
    assert!(
        drain_was_pending,
        "CONFIG_CAPACITY_OUTBOUND_SOCKET_LAST_HALF_RED: final TCP owner must block drain"
    );
}

#[tokio::test]
async fn observing_a_clone_does_not_retroactively_enroll_its_shared_pool() {
    let (server_binding, binding) = bindings();
    let observation = Arc::new(ConsensusBufferObservation::default());
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let server = SessionConsensusServer::new_insecure(handler.clone(), server_binding);
    let (handle, address) = observation
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("listen");
    let bare = RemoteSessionConsensusPeer::new_insecure(binding.clone(), address, None);
    let observed = bare
        .clone()
        .with_buffer_observation(Arc::clone(&observation));
    let (tasks_tx, mut tasks_rx) = tokio::sync::mpsc::unbounded_channel();
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let mut replies = Vec::new();
    for (peer, marker) in [(bare.clone(), 19), (observed.clone(), 23)] {
        let call = spawn_call(peer, request(&binding, marker), &tasks_tx);
        replies.push(
            tokio::time::timeout_at(guard, call)
                .await
                .expect("reply guard")
                .expect("caller joined")
                .expect("real reply")
                .result,
        );
    }
    let setup = tokio::time::timeout_at(guard, tasks_rx.recv())
        .await
        .expect("spawn capture guard")
        .expect("one actual unenrolled setup");
    tokio::time::timeout_at(guard, setup)
        .await
        .expect("join guard")
        .expect("setup joined");
    let unobserved = observation.outbound_socket_snapshot();
    let real_server = observation.inbound_socket_snapshot();
    let no_extra_attempt = tasks_rx.try_recv().is_err();
    drop(bare);
    drop(observed);
    tokio::time::timeout_at(guard, observation.wait_for_no_inbound_sockets())
        .await
        .expect("cached owner drop closes server before abort");
    handle.abort_and_drain_handlers_for_test().await;
    assert_eq!(replies, vec![Ok(vec![19]), Ok(vec![23])]);
    assert_eq!(handler.0.load(Ordering::Relaxed), 2);
    assert!(no_extra_attempt);
    assert_eq!(real_server.owners.len(), 1);
    assert!(unobserved.attempts.is_empty() && unobserved.sockets.is_empty());
    assert!(!unobserved.registration_exhausted);
    assert!(observation.outbound_socket_snapshot().sockets.is_empty());
}
