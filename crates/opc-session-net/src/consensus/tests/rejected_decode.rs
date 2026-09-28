//! Rejected inbound allocation checkpoints through the real TCP listener.
//!
//! These cases qualify raw/decoded Vec ownership and cancellation only. They
//! neither replace native consensus nor measure TLS or parser-internal scratch.

use std::collections::BTreeMap;

use super::*;
use crate::protocol::inbound_decode_observation::{self, Observation, Phase, Snapshot};

const EXPECTED_CONNECTION_LIMIT: usize = 128;
const READ_CHUNK_BYTES: usize = 8_192;
const PARTIAL_DECLARED_BYTES: usize = 4 * READ_CHUNK_BYTES + 1;
const PARTIAL_SENT_BYTES: usize = 2 * READ_CHUNK_BYTES;
const DECODED_PAYLOAD_BYTES: usize = READ_CHUNK_BYTES + 1;

async fn write_body(stream: &mut TcpStream, declared: usize, body: &[u8]) -> Result<(), String> {
    let result = tokio::time::timeout(DEFAULT_CONSENSUS_IDLE_TIMEOUT, async {
        stream
            .write_all(
                &u32::try_from(declared)
                    .expect("bounded frame length")
                    .to_be_bytes(),
            )
            .await?;
        stream.write_all(body).await?;
        Ok::<(), io::Error>(())
    })
    .await;
    match result {
        Ok(result) => result.map_err(|error| format!("write frame: {error}")),
        Err(_) => Err("write frame exceeded unchanged idle interval".to_owned()),
    }
}

async fn peer_closed(stream: &mut TcpStream) -> Result<(), String> {
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(DEFAULT_CONSENSUS_IDLE_TIMEOUT, stream.read(&mut byte)).await {
        Ok(Ok(0)) => Ok(()),
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Ok(Ok(_)) => Err("rejected frame unexpectedly produced response bytes".to_owned()),
        Ok(Err(error)) => Err(format!("read rejected connection: {error}")),
        Err(_) => Err("rejected connection exceeded unchanged idle interval".to_owned()),
    }
}

fn malformed_outer_frame(binding: &RemoteReplicaBinding) -> Vec<u8> {
    let outbound = SessionConsensusTransportRequest::Call {
        call_id: uuid::Uuid::from_u128(1),
        request: SessionConsensusWireRequest::try_new(
            binding.consensus_identity(),
            binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::ForwardMutation,
            vec![u8::MAX; DECODED_PAYLOAD_BYTES],
        )
        .expect("valid bounded inner request"),
    };
    let mut body = serde_json::to_vec(&outbound).expect("serialize synthetic Call");
    drop(outbound);
    assert!(body.ends_with(b"}}}"));
    // Leave the real inner request intact, then reject on a later outer field.
    // The trailing whitespace makes the raw body exactly the accepted ceiling.
    body.truncate(body.len() - 2);
    body.extend_from_slice(b",\"unexpected\":0}}");
    assert!(body.len() < MAX_NEGOTIATED_FRAME_SIZE);
    body.resize(MAX_NEGOTIATED_FRAME_SIZE, b' ');
    body
}

fn assert_union(snapshot: &Snapshot, expected: &BTreeMap<usize, usize>) {
    assert!(
        snapshot.aliases_agree,
        "actual aliases must agree on capacity"
    );
    assert_eq!(snapshot.distinct_allocations, expected.len());
    assert_eq!(
        snapshot.capacity,
        expected.values().sum::<usize>(),
        "REJECTED_DECODE_CAPACITY_RED: charge the simultaneous actual capacity union"
    );
    let observed: BTreeMap<_, _> = snapshot
        .owners
        .iter()
        .map(|owner| (owner.address, owner.capacity))
        .collect();
    assert_eq!(
        &observed, expected,
        "REJECTED_DECODE_IDENTITY_RED: retain exact borrowed allocation identities"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn oversize_declared_consensus_frame_rejects_before_body_allocation() {
    let (server_binding, client_binding) = bindings();
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let configured_connections = server.max_connections;
    let configured_frame = server.max_frame_size;
    let (handle, address) = server
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("listen with unchanged production defaults");
    let permits = Arc::clone(&handle.handler_executions);
    let mut client = raw_consensus_connection(address, &client_binding).await;
    let observation = Observation::new();
    let scope = inbound_decode_observation::install(&observation);
    // The extra byte plus EOF lets the fence-removal control finish its real
    // attempted body read without waiting out, or changing, a server deadline.
    let mut prefix_and_byte = [0_u8; 5];
    prefix_and_byte[..4].copy_from_slice(
        &u32::try_from(MAX_NEGOTIATED_FRAME_SIZE + 1)
            .expect("one-over frame")
            .to_be_bytes(),
    );
    prefix_and_byte[4] = b'{';
    let sent = client.write_all(&prefix_and_byte).await;
    let half_closed = client.shutdown().await;
    let closed = peer_closed(&mut client).await;
    drop(client);
    handle.abort_and_drain_handlers_for_test().await;
    let report = observation.report();
    drop(scope);
    let drained = permits.available_permits() == configured_connections;
    eprintln!("CONFIG_CAPACITY_REJECTED_DECODE_LIFECYCLE case=oversize connections_joined=true drained={drained} registered={} released={} full_memory_bound=false",
        report.registered, report.released);

    assert!(sent.is_ok(), "send exact over-limit prefix: {sent:?}");
    assert!(
        half_closed.as_ref().map_or_else(
            |error| matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
            ),
            |_| true,
        ),
        "half-close synthetic sender: {half_closed:?}"
    );
    assert!(
        closed.is_ok(),
        "real rejected connection must close: {closed:?}"
    );
    assert!(drained);
    assert_eq!(configured_connections, EXPECTED_CONNECTION_LIMIT);
    assert_eq!(configured_frame, MAX_NEGOTIATED_FRAME_SIZE);
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    assert!(report.current.owners.is_empty());
    assert_eq!(report.registered, report.released);
    assert!(report.release_identity_valid);
    assert_eq!(report.request_samples, 0);
    assert_eq!(report.decode_samples, 0);
    assert_eq!(
        report.registered, 0,
        "REJECTED_DECODE_PREFIX_RED: reject one-over length before allocating a body Vec"
    );
    eprintln!("CONFIG_CAPACITY_REJECTED_DECODE_OK case=oversize body_allocations=0 full_memory_bound=false");
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_consensus_frame_observes_raw_decoded_overlap_and_cancel_release() {
    let (server_binding, client_binding) = bindings();
    let body = malformed_outer_frame(&client_binding);
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let configured_connections = server.max_connections;
    let configured_frame = server.max_frame_size;
    let (handle, address) = server
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("listen with unchanged production defaults");
    let permits = Arc::clone(&handle.handler_executions);
    let mut malformed = raw_consensus_connection(address, &client_binding).await;
    let mut partial = raw_consensus_connection(address, &client_binding).await;
    let observation = Observation::new();
    let scope = inbound_decode_observation::install(&observation);
    let partial_sent = write_body(
        &mut partial,
        PARTIAL_DECLARED_BYTES,
        &[b' '; PARTIAL_SENT_BYTES],
    )
    .await;
    let waiting = tokio::time::timeout(
        DEFAULT_CONSENSUS_IDLE_TIMEOUT,
        observation.wait_for_raw_read(PARTIAL_DECLARED_BYTES, PARTIAL_SENT_BYTES),
    )
    .await;
    let sent = write_body(&mut malformed, body.len(), &body).await;
    drop(body);
    let closed = peer_closed(&mut malformed).await;
    drop(malformed);
    let before_cancel = observation.report();
    // Abort and join the real accepted connection that still lacks body bytes.
    // No fake handler or observer condition supplies this teardown barrier.
    handle.abort_and_drain_handlers_for_test().await;
    drop(partial);
    let report = observation.report();
    drop(scope);
    let drained = permits.available_permits() == configured_connections;
    eprintln!("CONFIG_CAPACITY_REJECTED_DECODE_LIFECYCLE case=malformed_cancel connections_joined=true drained={drained} registered={} released={} request_samples={} decode_samples={} full_memory_bound=false",
        report.registered, report.released, report.request_samples, report.decode_samples);

    assert!(
        partial_sent.is_ok(),
        "send real partial body: {partial_sent:?}"
    );
    assert!(
        waiting.is_ok(),
        "the real second reader must suspend with a partial Vec"
    );
    assert!(sent.is_ok(), "send bounded malformed frame: {sent:?}");
    assert!(
        closed.is_ok(),
        "real malformed connection must close: {closed:?}"
    );
    assert!(drained);
    assert_eq!(configured_connections, EXPECTED_CONNECTION_LIMIT);
    assert_eq!(configured_frame, MAX_NEGOTIATED_FRAME_SIZE);
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    assert!(
        report.current.owners.is_empty(),
        "all real reader borrows must end"
    );
    assert_eq!(report.registered, report.released);
    assert!(
        report.release_identity_valid,
        "REJECTED_DECODE_CAPACITY_RED: each registration must match its real Vec at release"
    );
    assert_eq!(report.request_samples, 1);
    assert_eq!(report.decode_samples, 1);
    let request = report.request.expect("one actual inner request checkpoint");
    let decode = report.decode.expect("one actual outer decode result");
    // This independent late read occurred in the borrowed guard's Drop before
    // cancellation freed the partial Vec. Its immutability proves the same
    // identity/capacity was live at the simultaneous decode checkpoint.
    let cancelled = report
        .last_read_release
        .expect("cancelled actual body owner");
    assert_eq!(Some(cancelled), waiting.ok());
    assert_eq!(cancelled.phase, Phase::ReadBody);
    assert_eq!(cancelled.declared, PARTIAL_DECLARED_BYTES);
    assert_eq!(cancelled.length, PARTIAL_SENT_BYTES);
    assert_eq!(before_cancel.current.owners, vec![cancelled]);
    assert!(decode.rejected, "outer unknown field must actually reject");
    assert_eq!(decode.length, MAX_NEGOTIATED_FRAME_SIZE);
    assert!(decode.capacity >= decode.length);
    assert_eq!(request.length, DECODED_PAYLOAD_BYTES);
    assert!(request.capacity >= request.length);
    assert_eq!(
        request.current.owners.len(),
        4,
        "REJECTED_DECODE_OWNER_RED: raw decode + partial read + two borrowed aliases of one decoded Vec"
    );
    assert_eq!(
        request
            .current
            .owners
            .iter()
            .filter(|owner| owner.phase == Phase::DecodedRequest)
            .count(),
        2
    );
    assert!(request.current.owners.contains(&cancelled));
    let raw = request
        .current
        .owners
        .iter()
        .find(|owner| owner.phase == Phase::DecodeRaw)
        .expect("actual raw owner at the same inner-decode checkpoint");
    assert_eq!(
        (raw.address, raw.length, raw.capacity),
        (decode.address, decode.length, decode.capacity)
    );
    for alias in request
        .current
        .owners
        .iter()
        .filter(|owner| owner.phase == Phase::DecodedRequest)
    {
        assert_eq!(
            (alias.address, alias.length, alias.capacity),
            (request.address, request.length, request.capacity)
        );
    }
    let expected = BTreeMap::from([
        (decode.address, decode.capacity),
        (cancelled.address, cancelled.capacity),
        (request.address, request.capacity),
    ]);
    assert_eq!(
        expected.len(),
        3,
        "three distinct actual live Vec allocations"
    );
    assert_union(&request.current, &expected);
    assert_union(
        &decode.current,
        &BTreeMap::from([
            (decode.address, decode.capacity),
            (cancelled.address, cancelled.capacity),
        ]),
    );
    eprintln!("CONFIG_CAPACITY_REJECTED_DECODE_OK case=malformed_cancel live_allocations={} raw_capacity={} decoded_capacity={} partial_capacity={} current_capacity={} full_memory_bound=false",
        request.current.distinct_allocations, decode.capacity, request.capacity,
        cancelled.capacity, request.current.capacity);
}
