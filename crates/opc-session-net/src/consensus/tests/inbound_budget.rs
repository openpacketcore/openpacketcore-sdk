//! Component qualification of the existing inbound handler execution budget.
//!
//! Real TCP/JSON requests retain their decoded Vecs after transport timeout.
//! This is a plaintext transport test, not native consensus or a TLS byte bound.

use std::collections::BTreeMap;

use super::*;

const EXPECTED_CONNECTION_LIMIT: usize = 128;
const PAYLOAD_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Allocation {
    request_id: u16,
    address: usize,
    capacity: usize,
    length: usize,
    valid_request: bool,
}

impl Allocation {
    fn read(request: &SessionConsensusWireRequest, sender: SessionConsensusNodeId) -> Self {
        let request_id = request
            .payload
            .get(..2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .unwrap_or_default();
        Self {
            request_id,
            address: request.payload.as_ptr() as usize,
            capacity: request.payload.capacity(),
            length: request.payload.len(),
            valid_request: request.sender == sender
                && request.family == SessionConsensusRpcFamily::ForwardMutation
                && request.payload.len() == PAYLOAD_BYTES
                && request.payload[2..].iter().all(|byte| *byte == u8::MAX),
        }
    }
}

#[derive(Debug)]
struct Inventory {
    live: BTreeMap<u16, Allocation>,
    duplicate_ids: usize,
    released: usize,
    release_identity_valid: bool,
}

/// The borrowed request stays alive through this registration. Only numbers
/// enter the inventory; no payload clone or retained command is an observer.
struct BorrowedInbound<'a> {
    request: &'a SessionConsensusWireRequest,
    sender: SessionConsensusNodeId,
    inventory: &'a StdMutex<Inventory>,
}

impl Drop for BorrowedInbound<'_> {
    fn drop(&mut self) {
        let actual = Allocation::read(self.request, self.sender);
        let mut inventory = self.inventory.lock().expect("inbound inventory");
        let removed = inventory.live.remove(&actual.request_id);
        inventory.release_identity_valid &= removed == Some(actual);
        inventory.released += 1;
    }
}

#[derive(Debug)]
struct RetainedInboundHandler {
    inventory: Arc<StdMutex<Inventory>>,
    release: tokio::sync::watch::Receiver<bool>,
    completed: tokio::sync::mpsc::Sender<Allocation>,
}

#[async_trait]
impl SessionConsensusRpcHandler for RetainedInboundHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        let allocation = Allocation::read(&request, authenticated_sender);
        {
            let mut inventory = self.inventory.lock().expect("inbound inventory");
            if inventory
                .live
                .insert(allocation.request_id, allocation)
                .is_some()
            {
                inventory.duplicate_ids += 1;
            }
        }
        let registration = BorrowedInbound {
            request: &request,
            sender: authenticated_sender,
            inventory: &self.inventory,
        };
        let mut release = self.release.clone();
        while !*release.borrow_and_update() {
            if release.changed().await.is_err() {
                break;
            }
        }
        let completed = Allocation::read(&request, authenticated_sender);
        drop(registration);
        drop(request);
        self.completed
            .try_send(completed)
            .expect("one completion per real request fits the bounded channel");
        SessionConsensusWireResponse {
            result: Err(SessionConsensusPeerError::Rejected),
        }
    }
}

async fn timed_out_call(
    address: SocketAddr,
    binding: RemoteReplicaBinding,
    request_id: u16,
) -> Result<(), String> {
    let mut stream = raw_consensus_connection(address, &binding).await;
    let mut payload = vec![u8::MAX; PAYLOAD_BYTES];
    payload[..2].copy_from_slice(&request_id.to_le_bytes());
    let call_id = uuid::Uuid::from_u128(u128::from(request_id));
    let outbound = SessionConsensusTransportRequest::Call {
        call_id,
        request: SessionConsensusWireRequest::try_new(
            binding.consensus_identity(),
            binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::ForwardMutation,
            payload,
        )
        .expect("bounded synthetic request"),
    };
    write_frame(&mut stream, &outbound)
        .await
        .map_err(|error| format!("write request {request_id}: {error}"))?;
    drop(outbound);
    let response =
        read_frame::<_, SessionConsensusTransportResponse>(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
            .await
            .map_err(|error| format!("read response {request_id}: {error}"))?;
    drop(stream);
    match response {
        SessionConsensusTransportResponse::Call {
            call_id: actual,
            response:
                SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Timeout),
                },
        } if actual == call_id => Ok(()),
        _ => Err(format!(
            "request {request_id} lacked its exact timeout response"
        )),
    }
}

async fn expire_calls(
    address: SocketAddr,
    binding: &RemoteReplicaBinding,
    ids: std::ops::RangeInclusive<u16>,
) -> Vec<Result<(), String>> {
    let mut clients = tokio::task::JoinSet::new();
    // Test hang guard covers setup, the unchanged handler interval, and the
    // response write interval. It changes no server or peer deadline.
    let hang_guard = DEFAULT_CONSENSUS_IDLE_TIMEOUT * 2 + DEFAULT_CONSENSUS_RPC_TIMEOUT;
    for request_id in ids {
        let binding = binding.clone();
        clients.spawn(async move {
            tokio::time::timeout(hang_guard, timed_out_call(address, binding, request_id))
                .await
                .unwrap_or_else(|_| {
                    Err(format!("request {request_id} exceeded the test hang guard"))
                })
        });
    }
    let mut outcomes = Vec::new();
    while let Some(joined) = clients.join_next().await {
        outcomes.push(joined.unwrap_or_else(|error| Err(format!("client task: {error}"))));
    }
    outcomes
}

fn unique_allocations(live: &BTreeMap<u16, Allocation>) -> BTreeMap<usize, usize> {
    live.values()
        .map(|owner| (owner.address, owner.capacity))
        .collect()
}

#[tokio::test]
async fn retained_inbound_handlers_obey_default_connection_budget_after_timeout() {
    let (server_binding, client_binding) = bindings();
    let inventory = Arc::new(StdMutex::new(Inventory {
        live: BTreeMap::new(),
        duplicate_ids: 0,
        released: 0,
        release_identity_valid: true,
    }));
    let (release_tx, release_rx) = tokio::sync::watch::channel(false);
    let (completed_tx, mut completed_rx) =
        tokio::sync::mpsc::channel(EXPECTED_CONNECTION_LIMIT + 1);
    let handler = Arc::new(RetainedInboundHandler {
        inventory: Arc::clone(&inventory),
        release: release_rx,
        completed: completed_tx,
    });
    let server = SessionConsensusServer::from_transport(
        handler.clone(),
        None,
        SessionMembershipAdmission::from_current_binding(server_binding),
    );
    let configured_connections = server.max_connections;
    let (handle, address) = server
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen with unchanged production defaults");
    let execution_permits = Arc::clone(&handle.handler_executions);
    let last_initial_id = u16::try_from(EXPECTED_CONNECTION_LIMIT).expect("bounded IDs");

    let initial = expire_calls(address, &client_binding, 1..=last_initial_id).await;
    let after_initial_timeouts = inventory.lock().expect("inbound inventory").live.clone();
    let over_id = last_initial_id + 1;
    let over = expire_calls(address, &client_binding, over_id..=over_id).await;
    let before_release = inventory.lock().expect("inbound inventory").live.clone();
    let unique = unique_allocations(&before_release);
    let current_payload_capacity: usize = unique.values().sum();

    release_tx.send_replace(true);
    let transport_drained = tokio::time::timeout(
        DEFAULT_CONSENSUS_IDLE_TIMEOUT,
        handle.abort_and_drain_handlers_for_test(),
    )
    .await
    .is_ok();
    drop(handler);
    // Closure of this channel also requires every detached handler's Arc to
    // drop. This barrier remains meaningful if the execution permit is lost.
    let mut completed = BTreeMap::new();
    let mut completion_count = 0;
    let handlers_drained = tokio::time::timeout(DEFAULT_CONSENSUS_IDLE_TIMEOUT, async {
        while let Some(allocation) = completed_rx.recv().await {
            completion_count += 1;
            completed.insert(allocation.request_id, allocation);
        }
    })
    .await
    .is_ok();
    let inventory = inventory.lock().expect("inbound inventory");
    let drained = transport_drained && handlers_drained && inventory.live.is_empty();
    let exact_timeouts = initial
        .iter()
        .chain(&over)
        .filter(|result| result.is_ok())
        .count();
    eprintln!(
        "CONFIG_CAPACITY_INBOUND_BUDGET_LIFECYCLE configured_connections={} exact_timeouts={} \
         retained_after_initial={} retained_after_over={} unique_payloads={} \
         current_payload_capacity={} released={} drained={} full_memory_bound=false",
        configured_connections,
        exact_timeouts,
        after_initial_timeouts.len(),
        before_release.len(),
        unique.len(),
        current_payload_capacity,
        inventory.released,
        drained,
    );

    assert!(
        drained,
        "all real transport and retained request owners must drain"
    );
    assert_eq!(configured_connections, EXPECTED_CONNECTION_LIMIT);
    assert_eq!(
        execution_permits.available_permits(),
        configured_connections
    );
    assert_eq!(initial.len(), EXPECTED_CONNECTION_LIMIT);
    assert_eq!(over.len(), 1);
    assert!(
        initial.iter().chain(&over).all(Result::is_ok),
        "{initial:?} {over:?}"
    );
    assert_eq!(inventory.duplicate_ids, 0);
    assert!(inventory.release_identity_valid);
    assert_eq!(inventory.released, completion_count);
    assert_eq!(
        completed, before_release,
        "completion must free the exact captured owners"
    );
    assert_eq!(after_initial_timeouts.len(), EXPECTED_CONNECTION_LIMIT);
    assert!(after_initial_timeouts
        .keys()
        .copied()
        .eq(1..=last_initial_id));
    assert!(before_release.values().all(|owner| {
        owner.valid_request
            && owner.address != 0
            && owner.length == PAYLOAD_BYTES
            && owner.capacity >= owner.length
    }));
    assert_eq!(
        unique.len(),
        before_release.len(),
        "live decoded Vecs must be distinct"
    );
    assert_eq!(
        before_release.len(),
        EXPECTED_CONNECTION_LIMIT,
        "CONFIG_CAPACITY_INBOUND_HANDLER_BOUND_RED: a timed-out handler must retain its execution permit until its actual request owner drains",
    );
    assert_eq!(before_release, after_initial_timeouts);
    eprintln!("CONFIG_CAPACITY_INBOUND_HANDLER_BOUND_PASS full_memory_bound=false");
}
