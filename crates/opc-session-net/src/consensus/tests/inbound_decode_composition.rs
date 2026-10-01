//! Joint real-TCP checks for the enrolled endpoint and actual outer decoder.
//! These are owner-lifetime and dispatch checks, not a TLS or fleet memory bound.

use super::*;
use crate::protocol::inbound_decode_observation::{self, Observation, Phase};
use crate::protocol::ConsensusDecodeDispatchCount;
use capacity_observation::{ConsensusBufferObservation, InboundSocketPhase};

const PAYLOAD_BYTES: usize = 8_193;
const PAYLOAD_MARKER: u8 = 197;
const PARTIAL_DECLARED_BYTES: usize = 4 * 8_192 + 1;
const PARTIAL_SENT_BYTES: usize = 2 * 8_192;

fn canonical_body(binding: &RemoteReplicaBinding) -> Vec<u8> {
    serde_json::to_vec(&SessionConsensusTransportRequest::Call {
        call_id: uuid::Uuid::from_u128(7),
        request: SessionConsensusWireRequest::try_new(
            binding.consensus_identity(),
            binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::ForwardMutation,
            vec![PAYLOAD_MARKER; PAYLOAD_BYTES],
        )
        .expect("bounded synthetic request"),
    })
    .expect("canonical wire body")
}

async fn write_body(
    stream: &mut TcpStream,
    declared: usize,
    body: &[u8],
    guard: tokio::time::Instant,
) -> Result<(), String> {
    tokio::time::timeout_at(guard, async {
        stream
            .write_all(&u32::try_from(declared).expect("bounded body").to_be_bytes())
            .await?;
        stream.write_all(body).await
    })
    .await
    .map_err(|_| "body-write harness guard elapsed".to_owned())?
    .map_err(|error| format!("body write: {error}"))
}

#[derive(Debug)]
struct PayloadReceipt {
    address: usize,
    length: usize,
    capacity: usize,
    contents_match: bool,
}

#[derive(Debug)]
struct HeldDecodedHandler {
    entered: tokio::sync::mpsc::Sender<PayloadReceipt>,
    release: Semaphore,
}

#[async_trait]
impl SessionConsensusRpcHandler for HeldDecodedHandler {
    async fn handle(
        &self,
        _authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.entered
            .try_send(PayloadReceipt {
                address: request.payload.as_ptr() as usize,
                length: request.payload.len(),
                capacity: request.payload.capacity(),
                contents_match: request.payload.iter().all(|byte| *byte == PAYLOAD_MARKER),
            })
            .expect("one real handler entry");
        self.release.acquire().await.expect("test release").forget();
        SessionConsensusWireResponse {
            result: Ok(request.payload),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn enrolled_tcp_keeps_its_owner_through_large_canonical_decode_and_reply() {
    let (server_binding, client_binding) = bindings();
    let body = canonical_body(&client_binding);
    let endpoints = Arc::new(ConsensusBufferObservation::default());
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(1);
    let handler = Arc::new(HeldDecodedHandler {
        entered: entered_tx,
        release: Semaphore::new(0),
    });
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let configured_connections = server.max_connections;
    let (handle, address) = endpoints
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("original server limits");
    let permits = Arc::clone(&handle.handler_executions);
    let mut client = raw_consensus_connection(address, &client_binding).await;
    let bootstrapped = endpoints.inbound_socket_snapshot();
    // The real listener runs on this current-thread runtime. Install after
    // bootstrap so the count covers exactly this request's shared DTO decode.
    let allocations = Observation::new();
    let scope = inbound_decode_observation::install(&allocations);
    let dispatch = ConsensusDecodeDispatchCount::start();
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let sent = write_body(&mut client, body.len(), &body, guard).await;
    let entered = tokio::time::timeout_at(guard, entered_rx.recv()).await;
    let held = endpoints.inbound_socket_snapshot();
    let decoded = allocations.report();
    let elements = dispatch.finish();
    handler.release.add_permits(1);
    let reply = tokio::time::timeout_at(
        guard,
        read_frame::<_, SessionConsensusTransportResponse>(&mut client, MAX_NEGOTIATED_FRAME_SIZE),
    )
    .await;
    drop(client);
    handle.abort_and_drain_handlers_for_test().await;
    let drained = endpoints.inbound_socket_snapshot();
    let released = allocations.report();
    drop(scope);
    let handlers_drained = permits.available_permits() == configured_connections;
    println!(
        "CONFIG_CAPACITY_INBOUND_DECODE_JOINT_LIFECYCLE case=canonical payload_bytes={PAYLOAD_BYTES} observed_endpoints={} sequence_elements={elements} joined=true handlers_drained={handlers_drained} endpoints_drained={} allocation_owners_drained={} full_memory_bound=false",
        held.owners.len(), drained.owners.is_empty(), released.current.owners.is_empty(),
    );

    // All causal assertions follow real connection/handler destruction.
    assert!(sent.is_ok(), "real request write: {sent:?}");
    let receipt = entered.expect("handler guard").expect("real handler entry");
    let SessionConsensusTransportResponse::Call { call_id, response } =
        reply.expect("reply guard").expect("real reply");
    assert_eq!(call_id, uuid::Uuid::from_u128(7));
    assert_eq!(response.result, Ok(vec![PAYLOAD_MARKER; PAYLOAD_BYTES]));
    assert!(handlers_drained);
    assert!(drained.owners.is_empty());
    assert!(!drained.registration_exhausted);
    assert!(released.current.owners.is_empty());
    assert_eq!(released.registered, released.released);
    assert!(released.release_identity_valid);
    assert_eq!(
        held.owners.len(),
        1,
        "CONFIG_CAPACITY_INBOUND_DECODE_SOCKET_RED: real handler retains one enrolled endpoint"
    );
    assert_eq!(held, bootstrapped, "same endpoint survives the real decode");
    assert_eq!(held.owners[0].phase, InboundSocketPhase::Negotiated);
    assert_eq!(
        elements, 0,
        "CONFIG_CAPACITY_INBOUND_DECODE_DISPATCH_RED: canonical receive must avoid per-byte Serde dispatch"
    );
    assert_eq!(decoded.request_samples, 1);
    assert_eq!(decoded.decode_samples, 1);
    let request = decoded.request.expect("actual request checkpoint");
    let raw = decoded.decode.expect("actual outer decode checkpoint");
    assert!(!raw.rejected);
    assert!(receipt.contents_match);
    assert_eq!(receipt.length, PAYLOAD_BYTES);
    assert_eq!(
        (request.address, request.length, request.capacity),
        (receipt.address, receipt.length, receipt.capacity),
        "the sampled Vec moved into the actual handler"
    );
    assert_eq!(raw.length, body.len());
    assert_ne!(raw.address, request.address);
    assert_eq!(request.current.distinct_allocations, 2);
    assert!(request.current.aliases_agree);
    assert_eq!(request.current.capacity, raw.capacity + receipt.capacity);
    assert!(request
        .current
        .owners
        .iter()
        .any(|owner| { owner.phase == Phase::DecodeRaw && owner.address == raw.address }));
    println!("CONFIG_CAPACITY_INBOUND_DECODE_JOINT_OK case=canonical real_reply=true same_payload_owner=true full_memory_bound=false");
}

#[tokio::test(flavor = "current_thread")]
async fn enrolled_tcp_rejects_noncanonical_outer_field_and_joins_partial_body_owner() {
    let (server_binding, client_binding) = bindings();
    let mut body = canonical_body(&client_binding);
    assert!(body.ends_with(b"}}}"));
    body.truncate(body.len() - 2);
    body.extend_from_slice(b",\"unexpected\":0}}");
    let endpoints = Arc::new(ConsensusBufferObservation::default());
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let configured_connections = server.max_connections;
    let (handle, address) = endpoints
        .scope_inbound_sockets(server.listen("127.0.0.1:0".parse().expect("loopback")))
        .await
        .expect("original server limits");
    let permits = Arc::clone(&handle.handler_executions);
    let mut malformed = raw_consensus_connection(address, &client_binding).await;
    let mut partial = raw_consensus_connection(address, &client_binding).await;
    let allocations = Observation::new();
    let scope = inbound_decode_observation::install(&allocations);
    let guard = tokio::time::Instant::now() + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    let partial_sent = write_body(
        &mut partial,
        PARTIAL_DECLARED_BYTES,
        &[b' '; PARTIAL_SENT_BYTES],
        guard,
    )
    .await;
    let waiting = tokio::time::timeout_at(
        guard,
        allocations.wait_for_raw_read(PARTIAL_DECLARED_BYTES, PARTIAL_SENT_BYTES),
    )
    .await;
    let simultaneous = endpoints.inbound_socket_snapshot();
    let dispatch = ConsensusDecodeDispatchCount::start();
    let sent = write_body(&mut malformed, body.len(), &body, guard).await;
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout_at(guard, malformed.read(&mut byte)).await;
    let elements = dispatch.finish();
    drop(malformed);
    let before_cancel = allocations.report();
    handle.abort_and_drain_handlers_for_test().await;
    drop(partial);
    let drained = endpoints.inbound_socket_snapshot();
    let released = allocations.report();
    drop(scope);
    let handlers_drained = permits.available_permits() == configured_connections;
    println!(
        "CONFIG_CAPACITY_INBOUND_DECODE_JOINT_LIFECYCLE case=reject_cancel payload_bytes={PAYLOAD_BYTES} observed_endpoints={} sequence_elements={elements} joined=true handlers_drained={handlers_drained} endpoints_drained={} allocation_owners_drained={} full_memory_bound=false",
        simultaneous.owners.len(), drained.owners.is_empty(), released.current.owners.is_empty(),
    );

    assert!(partial_sent.is_ok(), "partial-body write: {partial_sent:?}");
    let waiting = waiting.expect("actual partial-body reader checkpoint");
    assert!(sent.is_ok(), "malformed-body write: {sent:?}");
    assert!(
        matches!(closed, Ok(Ok(0)))
            || matches!(closed, Ok(Err(ref error)) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof)),
        "real refusal closes its endpoint: {closed:?}"
    );
    assert!(handlers_drained);
    assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    assert!(drained.owners.is_empty());
    assert!(!drained.registration_exhausted);
    assert!(released.current.owners.is_empty());
    assert_eq!(released.registered, released.released);
    assert!(released.release_identity_valid);
    assert_eq!(
        simultaneous.owners.len(), 2,
        "CONFIG_CAPACITY_INBOUND_DECODE_SOCKET_RED: both real endpoints survive through the partial read"
    );
    assert!(simultaneous
        .owners
        .iter()
        .all(|owner| owner.phase == InboundSocketPhase::Negotiated));
    assert_ne!(
        simultaneous.owners[0].socket_id,
        simultaneous.owners[1].socket_id
    );
    assert_eq!(
        elements, PAYLOAD_BYTES,
        "noncanonical outer fields retain original Serde rejection"
    );
    assert_eq!(released.request_samples, 1);
    assert_eq!(released.decode_samples, 1);
    assert_eq!(released.last_read_release, Some(waiting));
    assert_eq!(before_cancel.current.owners, vec![waiting]);
    let request = released.request.expect("real fallback inner request");
    let raw = released.decode.expect("real rejected outer decode");
    assert!(raw.rejected);
    assert_eq!(request.length, PAYLOAD_BYTES);
    assert_eq!(raw.length, body.len());
    assert_eq!(request.current.distinct_allocations, 3);
    assert!(request.current.aliases_agree);
    assert!(request.current.owners.contains(&waiting));
    assert_eq!(
        request.current.capacity,
        raw.capacity + request.capacity + waiting.capacity
    );
    println!("CONFIG_CAPACITY_INBOUND_DECODE_JOINT_OK case=reject_cancel handler_calls=0 partial_owner_released=true full_memory_bound=false");
}
