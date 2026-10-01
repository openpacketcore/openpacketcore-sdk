//! Real TLS provenance qualification with the shared original-receipt ledger.

use super::inbound_sockets::material_fixture_bindings;
use super::outbound_sockets::ready_cached_lanes_observed;
use super::*;
use capacity_observation::{
    ConsensusBufferObservation, TlsAllocationObserver, TlsAllocationSource,
};
use std::future::Future;

const OWNER_LIMIT: usize = 64;
const RECEIPT_LIMIT: usize = 16_384;
// Force chained collisions and free-list reuse in every original real-I/O
// detector. The fleet uses a larger table with the identical implementation.
const RECEIPT_BUCKETS: usize = 1;
static SERIAL_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/support/tls_receipts.rs"
));

fn print_snapshot(checkpoint: &str, snapshot: &Snapshot) {
    for owner in &snapshot.owners {
        println!(
            "CONFIG_CAPACITY_TLS_SAMPLE checkpoint={} owner={} source={:?} material={:?} source_group={} object={} wrapped={} allocations={} runtime_object={} runtime_wrapped={} split_object={} split_wrapped={} visible={} closed={} cross_thread_frees={} foreign_source_frees={} unscoped_frees={} origins={:?} retired={:?}",
            checkpoint, owner.row.id, owner.row.source, owner.row.material, owner.row.tls_group,
            owner.tls.object, owner.tls.wrapped, owner.tls.allocations,
            owner.socket.object, owner.socket.wrapped, owner.owner_storage.object,
            owner.owner_storage.wrapped, owner.row.visible, owner.row.closed,
            owner.row.cross_thread_frees, owner.row.foreign_source_frees, owner.row.unscoped_frees,
            owner.row.origins,
            owner.row.retired,
        );
    }
}

fn assert_live(snapshot: &Snapshot, expected: usize) {
    assert_eq!(
        connection_rows(snapshot).count(),
        expected,
        "CONFIG_CAPACITY_TLS_OWNER_OMISSION_RED"
    );
    assert!(
        connection_rows(snapshot).all(|owner| owner.row.visible && !owner.row.closed),
        "CONFIG_CAPACITY_TLS_OWNER_EARLY_RETIREMENT_RED"
    );
    assert_conserved(snapshot);
    assert!(
        connection_rows(snapshot).all(|owner| owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_ORIGINAL_STORAGE_RED"
    );
    assert_eq!(
        material_rows(snapshot).count(),
        expected,
        "CONFIG_CAPACITY_TLS_MATERIAL_OMISSION_RED"
    );
    for connection in connection_rows(snapshot) {
        let material = material_rows(snapshot)
            .find(|material| Some(material.row.id) == connection.row.material)
            .expect("CONFIG_CAPACITY_TLS_MATERIAL_LINK_RED");
        assert!(
            material.row.closed && !material.row.visible,
            "material construction has ended independently of allocation lifetime"
        );
        assert!(
            material.row.origins[TlsAllocationPhase::MaterialConstruct as usize].object > 0,
            "CONFIG_CAPACITY_TLS_MATERIAL_SCOPE_RED"
        );
    }
}

fn assert_material_retained(snapshot: &Snapshot) {
    assert!(
        material_rows(snapshot).all(|owner| owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_MATERIAL_STORAGE_RED"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtls_allocations_follow_ready_cache_and_application_io() {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let mut checkpoints = Vec::new();
    ready_cached_lanes_observed(true, observation, |name| {
        if name != "drained" {
            checkpoints.push((name, receipts.snapshot()));
        }
    })
    .await;
    tokio::time::timeout_at(guard, receipts.wait_for_drain())
        .await
        .expect("original TLS receipt cleanup guard");
    checkpoints.push(("drained", receipts.snapshot()));
    // The unchanged fixture completed authenticated Hello/Ack, three exact
    // application replies, both setup joins and server cleanup before assertions.
    println!("CONFIG_CAPACITY_TLS_MTLS_LIFECYCLE original_fixture=true replies=3 setup_joins=2 real_cleanup=true");
    for (name, sample) in &checkpoints {
        print_snapshot(name, sample);
        if *name == "drained" {
            assert_drained(sample);
        } else {
            assert_live(
                sample,
                if matches!(*name, "ready" | "first_active") {
                    2
                } else {
                    4
                },
            );
            for material in material_rows(sample) {
                // The pinned TLS 1.3 server traffic state no longer owns its
                // frozen config, and final bootstrap admission drops the SDK
                // handshake. The client traffic state retains its config.
                // Both lifetimes conserve the original allocation/free receipts.
                match material.row.source {
                    Some(TlsAllocationSource::InboundMaterial(_)) => assert_eq!(
                        material.tls,
                        Extent::ZERO,
                        "CONFIG_CAPACITY_TLS_SERVER_MATERIAL_RETIREMENT_RED"
                    ),
                    Some(TlsAllocationSource::OutboundMaterial(_)) => assert!(
                        material.tls.object > 0,
                        "CONFIG_CAPACITY_TLS_MATERIAL_STORAGE_RED"
                    ),
                    _ => unreachable!("material_rows selects only material sources"),
                }
            }
            assert!(connection_rows(sample).all(|owner| owner.row.established));
        }
    }
    let (_, final_sample) = checkpoints.last().expect("unchanged fixture checkpoints");
    assert_eq!(checkpoints.len(), 6);
    for owner in connection_rows(final_sample) {
        for phase in [
            TlsAllocationPhase::Construct,
            TlsAllocationPhase::HandshakePoll,
            TlsAllocationPhase::Write,
        ] {
            assert!(
                owner.row.origins[phase as usize].object > 0,
                "CONFIG_CAPACITY_TLS_PHASE_SCOPE_RED: actual TLS path produced no source receipts"
            );
        }
        assert!(
            owner.row.origins[TlsAllocationPhase::OwnerStorage as usize].object > 0,
            "CONFIG_CAPACITY_TLS_SPLIT_SCOPE_RED"
        );
        assert!(owner.row.scopes[TlsAllocationPhase::Read as usize] > 0);
        assert!(
            owner.row.frees[TlsAllocationPhase::StreamDrop as usize] > 0,
            "CONFIG_CAPACITY_TLS_STREAM_DROP_SCOPE_RED"
        );
    }
}

async fn cancelled_accept(poll_handshake: bool) {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let (_, binding) = material_fixture_bindings();
    let material =
        crate::test_support::RotatableServerMaterial::new(binding.remote_spiffe_id().as_str());
    let config = material.config();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let address = listener.local_addr().expect("address");
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let (raw, accepted) = tokio::time::timeout_at(guard, async {
        tokio::join!(TcpStream::connect(address), listener.accept())
    })
    .await
    .expect("real TCP pair guard");
    let mut raw = raw.expect("raw client");
    let (stream, _) = accepted.expect("accepted socket");
    let stream = capacity_observation::InboundSocket::new(stream, Some(&observation));
    let numeric_socket_context = stream.context();
    let material_owner = stream.tls_material_owner();
    let handshake = config
        .begin_handshake_observed(|construct| {
            TlsOwner::run(
                material_owner.as_ref(),
                TlsAllocationPhase::MaterialConstruct,
                construct,
            );
        })
        .expect("existing material snapshot");
    let material_context = material_owner.as_ref().map(TlsOwner::context);
    drop(material_owner);
    let owner = stream.tls_owner();
    TlsOwner::link_material(owner.as_ref(), material_context.as_ref());
    let mut stream = Some(TlsIo::new(stream, owner.as_ref()));
    let future = TlsOwner::run(owner.as_ref(), TlsAllocationPhase::Construct, || {
        tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(handshake.rustls_config()))
            .accept(stream.take().expect("constructor executes once"))
    });
    drop(handshake);
    let constructed = receipts.snapshot();
    let mut future = TlsHandshake::new(future, owner);
    let pending = if poll_handshake {
        std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut future).poll(cx).is_pending())).await
    } else {
        true
    };
    let stalled = receipts.snapshot();
    drop(future);
    let mut byte = [0_u8];
    let eof = tokio::time::timeout_at(guard, raw.read(&mut byte))
        .await
        .expect("cancelled TLS socket EOF guard")
        .expect("cancelled socket read");
    drop(raw);
    drop(listener);
    let drained = receipts.snapshot();
    assert!(pending);
    assert_eq!(eof, 0);
    assert!(observation.inbound_socket_snapshot().owners.is_empty());
    // Holding the numeric TCP context and both observers did not keep TLS alive.
    drop(numeric_socket_context);
    println!("CONFIG_CAPACITY_TLS_CANCEL_LIFECYCLE actual_accept=true polled={poll_handshake} future_dropped=true peer_eof=true");
    print_snapshot("constructed", &constructed);
    print_snapshot("stalled", &stalled);
    assert_live(&constructed, 1);
    assert_live(&stalled, 1);
    assert_material_retained(&constructed);
    assert_material_retained(&stalled);
    assert_drained(&drained);
    let owner = &connection_rows(&drained)
        .next()
        .expect("one TLS connection")
        .row;
    assert!(!owner.established);
    assert!(owner.origins[TlsAllocationPhase::Construct as usize].object > 0);
    if poll_handshake {
        assert!(
            owner.origins[TlsAllocationPhase::HandshakePoll as usize].object > 0,
            "CONFIG_CAPACITY_TLS_PHASE_SCOPE_RED"
        );
    } else {
        assert_eq!(owner.scopes[TlsAllocationPhase::HandshakePoll as usize], 0);
    }
    assert!(
        owner.frees[TlsAllocationPhase::HandshakeDrop as usize] > 0,
        "CONFIG_CAPACITY_TLS_HANDSHAKE_DROP_SCOPE_RED"
    );
}

#[tokio::test]
async fn stalled_tls_accept_keeps_receipts_until_future_cancellation() {
    cancelled_accept(true).await;
}

#[tokio::test]
async fn unpolled_tls_accept_drops_constructed_state_inside_owner_scope() {
    cancelled_accept(false).await;
}

#[tokio::test]
async fn mtls_last_split_half_drops_original_allocations_on_another_thread() {
    let _serial = SERIAL_TEST.lock().await;
    let receipts = Observation::new();
    let observation = Arc::new(ConsensusBufferObservation::default());
    receipts.attach(&observation);
    let (server_binding, binding) = material_fixture_bindings();
    let material =
        crate::test_support::RotatableServerMaterial::new(binding.remote_spiffe_id().as_str());
    let client_identity = server_binding
        .bind_remote(binding.local_replica_id().clone())
        .expect("reverse binding")
        .remote_spiffe_id()
        .clone();
    let client_config = material.trusted_client_config(client_identity.as_str());
    let server_config = material.config();
    let server_handshake = server_config.begin_handshake().expect("server material");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
    let address = listener.local_addr().expect("address");
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let client_tcp = capacity_observation::observe_outbound_attempt(
        Some(&observation),
        binding.local_consensus_node_id(),
        binding.remote_consensus_node_id(),
        async {
            let material_owner = capacity_observation::outbound_tls_material();
            let handshake = client_config
                .begin_handshake_observed(|construct| {
                    TlsOwner::run(
                        material_owner.as_ref(),
                        TlsAllocationPhase::MaterialConstruct,
                        construct,
                    );
                })
                .expect("client material");
            let context = material_owner.as_ref().map(TlsOwner::context);
            drop(material_owner);
            let socket = capacity_observation::OutboundSocket::new(
                TcpStream::connect(address).await.expect("connect"),
            );
            (socket, context, handshake)
        },
    );
    let (client, accepted) =
        tokio::time::timeout_at(guard, async { tokio::join!(client_tcp, listener.accept()) })
            .await
            .expect("real TCP pair guard");
    let (server, _) = accepted.expect("server socket");
    let (client, material_context, client_handshake) = client;
    let retained_material = client_handshake.rustls_config();
    let numeric_context = client.context();
    let owner = client.tls_owner();
    TlsOwner::link_material(owner.as_ref(), material_context.as_ref());
    let mut client = Some(TlsIo::new(client, owner.as_ref()));
    let connect = TlsOwner::run(owner.as_ref(), TlsAllocationPhase::Construct, || {
        let connector = tokio_rustls::TlsConnector::from(consensus_client_tls_config(
            client_handshake.rustls_config(),
        ));
        let name = ConsensusTarget::pinned(address)
            .tls_server_name(address)
            .expect("server name");
        connector.connect(name, client.take().expect("constructor executes once"))
    });
    drop(client_handshake);
    let acceptor = tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(
        server_handshake.rustls_config(),
    ));
    let (client, server) = tokio::time::timeout_at(guard, async {
        tokio::join!(TlsHandshake::new(connect, owner), acceptor.accept(server))
    })
    .await
    .expect("original TLS handshake guard");
    let client = client.expect("mutual TLS client");
    let mut server = server.expect("mutual TLS server");
    assert_eq!(
        client
            .inner()
            .expect("live stream")
            .get_ref()
            .1
            .alpn_protocol(),
        Some(SESSION_CONSENSUS_ALPN)
    );
    assert_eq!(
        server.get_ref().1.alpn_protocol(),
        Some(SESSION_CONSENSUS_ALPN)
    );
    let (mut reader, mut writer) = client.split().expect("original TLS split");
    let mut byte = [0_u8];
    tokio::time::timeout_at(guard, async {
        server.write_all(&[7]).await.expect("server TLS write");
        server.flush().await.expect("server TLS flush");
        reader.read_exact(&mut byte).await.expect("client TLS read");
    })
    .await
    .expect("real TLS read guard");
    assert_eq!(byte, [7]);
    let split = receipts.snapshot();
    let mut cancelled_drain = Box::pin(receipts.wait_for_drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(cancelled_drain.as_mut().poll(cx).is_pending()))
            .await
    );
    // A cancelled observer wait joins only its own waiter thread. It cannot
    // close a live TLS owner or retain the original stream or split halves.
    drop(cancelled_drain);
    drop(reader);
    let one_half = receipts.snapshot();
    tokio::time::timeout_at(guard, async {
        writer
            .write_all(&[9])
            .await
            .expect("remaining half TLS write");
        writer.flush().await.expect("remaining half TLS flush");
        server.read_exact(&mut byte).await.expect("server TLS read");
    })
    .await
    .expect("real final-half IO guard");
    assert_eq!(byte, [9]);
    tokio::time::timeout_at(guard, writer.shutdown())
        .await
        .expect("original TLS shutdown guard")
        .expect("TLS close_notify");
    let shutdown = receipts.snapshot();
    std::thread::spawn(move || drop(writer))
        .join()
        .expect("actual final-half destructor joined");
    let eof = tokio::time::timeout_at(guard, server.read(&mut byte))
        .await
        .expect("TLS peer EOF guard")
        .expect("TLS peer close_notify read");
    drop(server);
    drop(listener);
    let material_tail = receipts.snapshot();
    drop(retained_material);
    tokio::time::timeout_at(guard, receipts.wait_for_drain())
        .await
        .expect("original split receipt cleanup guard");
    let drained = receipts.snapshot();
    assert_eq!(eof, 0);
    let sockets = observation.outbound_socket_snapshot();
    assert!(sockets.attempts.is_empty() && sockets.sockets.is_empty());
    drop(numeric_context);
    println!("CONFIG_CAPACITY_TLS_SPLIT_LIFECYCLE mutual_tls=true actual_io_both_directions=true remaining_half_wrote=true close_notify=true destructor_thread_joined=true");
    for (name, sample) in [
        ("split", &split),
        ("one_half", &one_half),
        ("shutdown", &shutdown),
    ] {
        print_snapshot(name, sample);
        assert_live(sample, 1);
        assert_material_retained(sample);
        assert!(
            connection_rows(sample).all(|owner| owner.owner_storage.object > 0),
            "CONFIG_CAPACITY_TLS_SPLIT_SCOPE_RED"
        );
    }
    let split_owner = &connection_rows(&split)
        .next()
        .expect("split connection")
        .row;
    let one_half_owner = &connection_rows(&one_half)
        .next()
        .expect("remaining connection")
        .row;
    assert_eq!(split_owner.id, one_half_owner.id);
    assert_eq!(split_owner.source, one_half_owner.source);
    print_snapshot("material_tail", &material_tail);
    assert_conserved(&material_tail);
    assert!(
        connection_rows(&material_tail).all(|owner| owner.row.closed && owner.tls == Extent::ZERO)
    );
    assert!(
        material_rows(&material_tail).all(|owner| owner.row.closed && owner.tls.object > 0),
        "CONFIG_CAPACITY_TLS_MATERIAL_SHARED_TAIL_RED"
    );
    assert_drained(&drained);
    let owner = &connection_rows(&drained)
        .next()
        .expect("one TLS connection")
        .row;
    assert!(
        owner.cross_thread_frees > 0,
        "CONFIG_CAPACITY_TLS_CROSS_THREAD_SOURCE_RED"
    );
    assert!(
        owner.frees[TlsAllocationPhase::StreamDrop as usize] > 0,
        "CONFIG_CAPACITY_TLS_STREAM_DROP_SCOPE_RED"
    );
    assert!(owner.scopes[TlsAllocationPhase::Flush as usize] > 0);
    assert!(owner.scopes[TlsAllocationPhase::Shutdown as usize] > 0);
}
