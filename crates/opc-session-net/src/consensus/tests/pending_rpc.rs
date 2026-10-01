//! Actual pool/cold-acquisition waits and allocation identities; no native-operation claim.

use super::*;
use crate::consensus::capacity_observation::{
    scope, scope_typed_transport, ConsensusBufferObservation, PendingRpcCensus, PendingRpcPhase,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::task::Waker;

struct ResolverLifetime {
    active: Arc<AtomicUsize>,
    dropped: Arc<Notify>,
}

impl Drop for ResolverLifetime {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.dropped.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn pending_rpc_cold_acquisition_cancellation_and_timeout_conserve_payload() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let entered = entered.clone();
        let dropped = dropped.clone();
        let active = active.clone();
        Arc::new(move || {
            let entered = entered.clone();
            let dropped = dropped.clone();
            let active = active.clone();
            Box::pin(async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _lifetime = ResolverLifetime { active, dropped };
                entered.notify_one();
                std::future::pending::<io::Result<SocketAddr>>().await
            })
        })
    };
    let (_, binding) = bindings();
    let peer = RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::resolved(&binding, resolver),
        None,
        binding,
        None,
    )
    .with_buffer_observation(observation.clone());
    let cancelled_request = request(&peer, ConsensusRpcFamily::ForwardMutation, 1_048_577, 137);
    let timed_request = request(&peer, ConsensusRpcFamily::ReadBarrier, 19, 333);
    let queued_request = request(&peer, ConsensusRpcFamily::Vote, 29, 555);
    let expected = allocation_union([
        &cancelled_request.payload,
        &timed_request.payload,
        &queued_request.payload,
    ]);
    let after_cancel_expected = allocation_union([&timed_request.payload, &queued_request.payload]);
    let queued_capacity = queued_request.payload.capacity();
    let source = peer.binding.local_consensus_node_id();
    let target = peer.binding.remote_consensus_node_id();
    let mut cancelled =
        Box::pin(peer.call_with_timeout_inner(cancelled_request, Duration::from_secs(10)));
    assert!(poll_once(cancelled.as_mut()).is_pending());
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("the actual pending resolver starts before its physical setup deadline");
    let mut timed =
        Box::pin(peer.call_with_timeout_inner(timed_request, Duration::from_millis(300)));
    let mut queued =
        Box::pin(peer.call_with_timeout_inner(queued_request, Duration::from_secs(10)));
    assert!(poll_once(timed.as_mut()).is_pending());
    assert!(poll_once(queued.as_mut()).is_pending());
    let waiting = observation.pending_snapshot();
    drop(cancelled);
    let after_cancel = observation.pending_snapshot();
    // The released lane moves this actual caller from pool wait to cold wait.
    // Both cold callers now join the original physical attempt.
    assert!(poll_once(queued.as_mut()).is_pending());
    let after_lane = observation.pending_snapshot();
    tokio::time::advance(Duration::from_millis(300)).await;
    let timed_result = timed.await;
    let after_timeout = observation.pending_snapshot();
    drop(queued);
    let callers_drained = observation.pending_snapshot();
    let physical_attempt_still_active = active.load(Ordering::SeqCst);
    let permits = (
        peer.connection_pool.primary.in_flight.available_permits(),
        peer.connection_pool.overflow.in_flight.available_permits(),
    );
    drop(peer);
    // The pool's real shutdown cancels the supervised physical attempt. Its
    // lifetime is separate from the payload owners whose callers already left.
    let resolver_drained = tokio::time::timeout(Duration::from_secs(1), dropped.notified()).await;
    assert!(resolver_drained.is_ok());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(timed_result, Err(SessionConsensusPeerError::Timeout));
    assert_eq!(permits, (1, 1));
    assert_eq!(physical_attempt_still_active, 1);
    assert_eq!(callers_drained, PendingRpcCensus::default());
    assert_eq!(observation.pending_snapshot(), PendingRpcCensus::default());
    assert_eq!(observation.snapshot().live, Default::default());
    println!("CONFIG_CAPACITY_COLD_WAIT_LIFECYCLE cancelled=true timeout=true pool_to_cold=true lanes_released=2 physical_resolver_drained=true payloads_drained=true full_memory_bound=false");

    assert_eq!(waiting.owners.len(), 3, "CONFIG_CAPACITY_COLD_OWNER_RED");
    assert_eq!((waiting.rpc_allocations, waiting.rpc_bytes), expected);
    assert_eq!(waiting.additional_rpc_bytes, expected.1);
    assert_eq!(waiting.observed_rpc_bytes, expected.1);
    for sample in [&waiting, &after_cancel, &after_lane, &after_timeout] {
        assert!(sample.owners.iter().all(|owner| owner.source == source
            && owner.target == target
            && owner.generation == 0
            && !owner.selected_append));
    }
    assert_eq!(
        waiting
            .owners
            .iter()
            .map(|owner| (owner.family, owner.phase))
            .collect::<Vec<_>>(),
        vec![
            (
                ConsensusRpcFamily::ForwardMutation,
                PendingRpcPhase::ColdConnectionAcquire
            ),
            (
                ConsensusRpcFamily::ReadBarrier,
                PendingRpcPhase::ColdConnectionAcquire
            ),
            (ConsensusRpcFamily::Vote, PendingRpcPhase::PoolAcquire),
        ],
        "CONFIG_CAPACITY_COLD_PHASE_RED"
    );
    for sample in [&after_cancel, &after_lane] {
        assert_eq!(sample.owners.len(), 2);
        assert_eq!(
            (sample.rpc_allocations, sample.rpc_bytes),
            after_cancel_expected
        );
        assert_eq!(sample.observed_rpc_bytes, after_cancel_expected.1);
    }
    assert!(after_lane
        .owners
        .iter()
        .all(|owner| owner.phase == PendingRpcPhase::ColdConnectionAcquire));
    assert_eq!(after_timeout.owners.len(), 1);
    assert_eq!(after_timeout.owners[0].family, ConsensusRpcFamily::Vote);
    assert_eq!(
        after_timeout.owners[0].phase,
        PendingRpcPhase::ColdConnectionAcquire
    );
    assert_eq!(after_timeout.rpc_allocations, 1);
    assert_eq!(after_timeout.rpc_bytes, queued_capacity);
}

#[cfg(feature = "insecure-test")]
#[tokio::test]
async fn pending_rpc_cold_bootstrap_handoff_counts_payload_once() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let (server_binding, client_binding) = bindings();
    let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
    let hook = ConsensusAcceptedSetupHook::new();
    let mut server = SessionConsensusServer::new_insecure(handler.clone(), server_binding);
    server.post_accept_setup_hook = Some(hook.clone());
    let (handle, address) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let peer = RemoteSessionConsensusPeer::new_insecure(client_binding, address, None)
        .with_buffer_observation(observation.clone());
    let target = peer.binding.remote_consensus_node_id();
    let request = request(&peer, ConsensusRpcFamily::InstallSnapshot, 257, 1_019);
    let capacity = request.payload.capacity();
    let expected_payload = request.payload.clone();
    observation.hold_snapshot_writes(target);
    let mut call = Box::pin(peer.call_with_timeout_inner(request, Duration::from_secs(10)));
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = &mut call => return Err("call ended before held bootstrap"),
            () = hook.entered.notified() => {}
        }
        let cold = observation.pending_snapshot();
        hook.release.notify_one();
        tokio::select! {
            _ = &mut call => return Err("call ended before held negotiated frame"),
            () = observation.wait_for_snapshot_write(target) => {}
        }
        let negotiated_pending = observation.pending_snapshot();
        let negotiated = observation.snapshot().live;
        observation.release_snapshot_writes();
        let response = (&mut call).await;
        Ok((cold, negotiated_pending, negotiated, response))
    })
    .await;
    observation.release_snapshot_writes();
    drop(call);
    drop(peer);
    handle.abort_and_drain_handlers_for_test().await;
    let drained = observation.pending_snapshot();
    assert_eq!(drained, PendingRpcCensus::default());
    assert_eq!(observation.snapshot().live, Default::default());
    println!("CONFIG_CAPACITY_COLD_HANDOFF_LIFECYCLE listener_connections_joined=true handlers_drained=true payloads_drained=true full_memory_bound=false");

    let (cold, pending, negotiated, response) = result.unwrap().unwrap();
    assert_eq!(cold.owners.len(), 1, "CONFIG_CAPACITY_COLD_HANDOFF_RED");
    assert_eq!(cold.owners[0].phase, PendingRpcPhase::ColdConnectionAcquire);
    assert_eq!(cold.owners[0].family, ConsensusRpcFamily::InstallSnapshot);
    assert_eq!(cold.rpc_allocations, 1);
    assert_eq!(cold.rpc_bytes, capacity);
    assert_eq!(cold.observed_rpc_bytes, capacity);
    assert!(pending.owners.is_empty());
    assert_eq!(pending.rpc_bytes, 0);
    assert_eq!(pending.additional_rpc_bytes, 0);
    assert_eq!(pending.observed_rpc_bytes, capacity);
    assert_eq!(negotiated.calls, 1);
    assert_eq!(negotiated.rpc_bytes, capacity);
    assert_eq!(negotiated.ready_frames, 1);
    assert!(negotiated.frame_bytes > 0);
    assert_eq!(response.unwrap().result, Ok(expected_payload));
    assert_eq!(handler.0.load(Ordering::Relaxed), 1);
}

fn peer(observation: Arc<ConsensusBufferObservation>) -> RemoteSessionConsensusPeer {
    let (_, binding) = bindings();
    let resolver: RemoteAddrResolver = Arc::new(|| {
        Box::pin(async {
            panic!("pending-owner fixture must not start connection setup");
        })
    });
    RemoteSessionConsensusPeer::from_transport(
        ConsensusTarget::resolved(&binding, resolver),
        None,
        binding,
        None,
    )
    .with_buffer_observation(observation)
}

fn request(
    peer: &RemoteSessionConsensusPeer,
    family: ConsensusRpcFamily,
    bytes: usize,
    spare: usize,
) -> SessionConsensusWireRequest {
    // One real SDK codec output, then byte-preserving spare-capacity pressure.
    // These are synthetic RPC contents, not an encoded native engine request.
    let mut payload = opc_consensus::encode_bounded(&vec![0xA5_u8; bytes]).unwrap();
    payload.reserve_exact(spare);
    SessionConsensusWireRequest::try_new(
        peer.binding.consensus_identity(),
        peer.binding.local_consensus_node_id(),
        family,
        payload,
    )
    .unwrap()
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn allocation_union<'a>(payloads: impl IntoIterator<Item = &'a Vec<u8>>) -> (usize, usize) {
    // Independent oracle: inspect real Vec owners, never the observer registry.
    let allocations: BTreeMap<_, _> = payloads
        .into_iter()
        .filter(|payload| payload.capacity() != 0)
        .map(|payload| (payload.as_ptr() as usize, payload.capacity()))
        .collect();
    (allocations.len(), allocations.values().sum())
}

fn assert_pending(
    sample: &PendingRpcCensus,
    calls: usize,
    allocations: usize,
    bytes: usize,
    additional: usize,
    combined: usize,
) {
    assert_eq!(
        sample.owners.len(),
        calls,
        "CONFIG_CAPACITY_PENDING_RPC_RED: real pool wait owners"
    );
    assert_eq!(
        sample.rpc_allocations, allocations,
        "CONFIG_CAPACITY_PENDING_IDENTITY_RED: distinct actual Vec allocations"
    );
    assert_eq!(
        sample.rpc_bytes, bytes,
        "CONFIG_CAPACITY_PENDING_CAPACITY_RED: actual Vec capacity including spare bytes"
    );
    assert_eq!(
        sample.additional_rpc_bytes, additional,
        "CONFIG_CAPACITY_PENDING_UNION_RED: pending aliases add no duplicate backing"
    );
    assert_eq!(
        sample.observed_rpc_bytes, combined,
        "CONFIG_CAPACITY_PENDING_UNION_RED: coherent pending/negotiated allocation union"
    );
    let ids: BTreeSet<_> = sample.owners.iter().map(|owner| owner.call_id).collect();
    assert_eq!(ids.len(), calls);
    assert!(ids.iter().all(|id| *id > 0));
    assert!(sample
        .owners
        .iter()
        .all(|owner| owner.phase == PendingRpcPhase::PoolAcquire));
}

#[tokio::test(start_paused = true)]
async fn pending_rpc_call_wait_cancellation_timeout_and_lane_release() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let peer = peer(observation.clone());
    let primary = peer.connection_pool.acquire().await;
    let overflow = peer.connection_pool.acquire().await;
    let cancelled_request = request(&peer, ConsensusRpcFamily::ReadBarrier, 17, 211);
    let timed_request = request(&peer, ConsensusRpcFamily::Vote, 29, 431);
    let mut released_request = request(&peer, ConsensusRpcFamily::ForwardMutation, 43, 877);
    // The real call validates this after acquiring its lane. It must preserve
    // Protocol, never reach setup, and release the lane without a second RPC.
    released_request.schema_version += 1;
    let expected = allocation_union([
        &cancelled_request.payload,
        &timed_request.payload,
        &released_request.payload,
    ]);
    let after_cancel_expected =
        allocation_union([&timed_request.payload, &released_request.payload]);
    let released_capacity = released_request.payload.capacity();
    let expected_rows = [
        (
            cancelled_request.family,
            cancelled_request.payload.capacity(),
        ),
        (timed_request.family, timed_request.payload.capacity()),
        (released_request.family, released_capacity),
    ];
    let source = peer.binding.local_consensus_node_id();
    let target = peer.binding.remote_consensus_node_id();
    let mut cancelled =
        Box::pin(peer.call_with_timeout_inner(cancelled_request, Duration::from_secs(10)));
    let mut timed = Box::pin(peer.call_with_timeout_inner(timed_request, Duration::from_secs(1)));
    let mut released =
        Box::pin(peer.call_with_timeout_inner(released_request, Duration::from_secs(10)));
    assert!(poll_once(cancelled.as_mut()).is_pending());
    assert!(poll_once(timed.as_mut()).is_pending());
    assert!(poll_once(released.as_mut()).is_pending());
    let waiting = observation.pending_snapshot();
    drop(cancelled);
    let after_cancel = observation.pending_snapshot();
    tokio::time::advance(Duration::from_secs(1)).await;
    let timed_result = timed.await;
    let after_timeout = observation.pending_snapshot();
    drop(overflow);
    let released_result = released.await;
    let after_release = observation.pending_snapshot();
    drop(primary);
    let permits = (
        peer.connection_pool.primary.in_flight.available_permits(),
        peer.connection_pool.overflow.in_flight.available_permits(),
    );
    let no_setup = matches!(
        peer.connection_pool
            .cold_connection
            .state
            .lock()
            .await
            .phase,
        ConsensusColdConnectionPhase::Idle
    );
    drop(peer);
    let drained = observation.pending_snapshot();
    assert_eq!(timed_result, Err(SessionConsensusPeerError::Timeout));
    assert_eq!(released_result, Err(SessionConsensusPeerError::Protocol));
    assert_eq!(permits, (1, 1));
    assert!(no_setup);
    assert_eq!(drained, PendingRpcCensus::default());
    println!("CONFIG_CAPACITY_PENDING_RPC_LIFECYCLE cancelled=true timeout=true protocol_preserved=true lanes_released=2 setup=false drained=true");

    assert_eq!(expected.0, 3, "fixture owns three distinct actual Vecs");
    assert_pending(&waiting, 3, expected.0, expected.1, expected.1, expected.1);
    assert_pending(
        &after_cancel,
        2,
        after_cancel_expected.0,
        after_cancel_expected.1,
        after_cancel_expected.1,
        after_cancel_expected.1,
    );
    assert_pending(
        &after_timeout,
        1,
        1,
        released_capacity,
        released_capacity,
        released_capacity,
    );
    assert_eq!(after_release, PendingRpcCensus::default());
    for (family, capacity) in expected_rows {
        let owner = waiting
            .owners
            .iter()
            .find(|owner| owner.family == family)
            .unwrap();
        assert_eq!(owner.source, source);
        assert_eq!(owner.target, target);
        assert_eq!(owner.rpc_bytes, capacity);
        assert_eq!(owner.generation, 0);
        assert!(!owner.selected_append);
    }
}

async fn actual_frame(
    observation: &Arc<ConsensusBufferObservation>,
    request: &SessionConsensusWireRequest,
    target: SessionConsensusNodeId,
    writer: &mut tokio::io::DuplexStream,
    generation: u64,
) -> Result<(), ProtocolError> {
    // Synthetic provenance selects the existing frame gates only. This is not
    // a native snapshot-input measurement or an engine acknowledgment.
    let snapshot_bytes = if request.family == ConsensusRpcFamily::InstallSnapshot {
        request.payload.capacity()
    } else {
        0
    };
    scope_typed_transport(
        request.family == ConsensusRpcFamily::AppendEntries,
        snapshot_bytes,
        generation,
        async {
            let owner = observation
                .observe_call(request.sender, target, request.family, &request.payload)
                .unwrap();
            scope(
                Some(&owner),
                write_frame_bounded_until(
                    writer,
                    &request.payload,
                    MIN_SESSION_CONSENSUS_FRAME_SIZE,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                ),
            )
            .await
        },
    )
    .await
}

#[tokio::test(start_paused = true)]
async fn pending_rpc_native_capture_unions_aliases_after_real_pool_wait() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let peer = peer(observation.clone());
    let source = peer.binding.local_consensus_node_id();
    let append_target = peer.binding.remote_consensus_node_id();
    let snapshot_target = SessionConsensusNodeId::new(3).unwrap();
    assert_ne!(append_target, snapshot_target);
    let append = request(&peer, ConsensusRpcFamily::AppendEntries, 1_048_577, 307);
    let snapshot = request(&peer, ConsensusRpcFamily::InstallSnapshot, 257, 701);
    // Equal content but genuinely independent backing, not another length term.
    let mut separate = snapshot.clone();
    separate.payload.reserve_exact(1_401);
    let pending_expected =
        allocation_union([&snapshot.payload, &snapshot.payload, &separate.payload]);
    let combined_expected =
        allocation_union([&append.payload, &snapshot.payload, &separate.payload]);
    let negotiated_expected = allocation_union([&append.payload, &snapshot.payload]);
    let separate_capacity = separate.payload.capacity();
    let primary = peer.connection_pool.acquire().await;
    let overflow = peer.connection_pool.acquire().await;
    observation.hold_snapshot_writes(snapshot_target);
    observation.hold_native_append_writes(source, append_target);
    let (mut append_tx, mut append_rx) = tokio::io::duplex(65_536);
    let (mut snapshot_tx, mut snapshot_rx) = tokio::io::duplex(65_536);
    let mut append_write = Box::pin(actual_frame(
        &observation,
        &append,
        append_target,
        &mut append_tx,
        41,
    ));
    let mut snapshot_write = Box::pin(actual_frame(
        &observation,
        &snapshot,
        snapshot_target,
        &mut snapshot_tx,
        42,
    ));
    assert!(poll_once(snapshot_write.as_mut()).is_pending());
    assert!(poll_once(append_write.as_mut()).is_pending());

    // The shared helper is the production pool-acquisition path. Borrowed
    // aliases qualify deduplication; this does not claim the SDK duplicates a
    // native request into these phases. Both lanes are actually occupied.
    let mut alias_one = Box::pin(peer.connection_pool.acquire_observed(
        Some(&observation),
        append_target,
        &snapshot,
    ));
    let mut alias_two = Box::pin(peer.connection_pool.acquire_observed(
        Some(&observation),
        append_target,
        &snapshot,
    ));
    let mut distinct = Box::pin(peer.connection_pool.acquire_observed(
        Some(&observation),
        append_target,
        &separate,
    ));
    assert!(poll_once(alias_one.as_mut()).is_pending());
    assert!(poll_once(alias_two.as_mut()).is_pending());
    assert!(poll_once(distinct.as_mut()).is_pending());
    // This is the same locked capture called by the real native observer.
    // The local test supplies real frames/pool waits, not a native mutation.
    let captured = observation.capture_native_overlap_and_release(source);
    drop(alias_one);
    let one_alias = observation.pending_snapshot();
    drop(alias_two);
    let no_alias = observation.pending_snapshot();
    drop(overflow);
    let acquired = distinct.await;
    let after_acquire = observation.pending_snapshot();
    drop(acquired);
    drop(primary);

    let (append_result, snapshot_result, append_read, snapshot_read) = tokio::join!(
        append_write,
        snapshot_write,
        read_frame::<_, Vec<u8>>(&mut append_rx, MIN_SESSION_CONSENSUS_FRAME_SIZE),
        read_frame::<_, Vec<u8>>(&mut snapshot_rx, MIN_SESSION_CONSENSUS_FRAME_SIZE),
    );
    let exact_wire = append_read
        .as_ref()
        .is_ok_and(|value| value == &append.payload)
        && snapshot_read
            .as_ref()
            .is_ok_and(|value| value == &snapshot.payload);
    let permits = (
        peer.connection_pool.primary.in_flight.available_permits(),
        peer.connection_pool.overflow.in_flight.available_permits(),
    );
    drop((append_read, snapshot_read, append, snapshot, separate));
    drop((append_tx, append_rx, snapshot_tx, snapshot_rx, peer));
    let drained = observation.pending_snapshot();
    let frames_drained = observation.snapshot().live;
    append_result.unwrap();
    snapshot_result.unwrap();
    assert!(exact_wire);
    assert_eq!(permits, (1, 1));
    assert_eq!(drained, PendingRpcCensus::default());
    assert_eq!(frames_drained, Default::default());
    println!("CONFIG_CAPACITY_PENDING_UNION_LIFECYCLE actual_frames=2 exact_wire=true cancelled_waits=2 acquired_waits=1 lanes_released=2 drained=true");

    let captured = captured.expect("actual selected frame pair before local cleanup");
    assert_eq!(pending_expected.0, 2);
    assert_eq!(combined_expected.0, 3);
    assert_pending(
        &captured.pending,
        3,
        pending_expected.0,
        pending_expected.1,
        separate_capacity,
        combined_expected.1,
    );
    assert_eq!(captured.current.total.rpc_bytes, negotiated_expected.1);
    assert_pending(
        &one_alias,
        2,
        pending_expected.0,
        pending_expected.1,
        separate_capacity,
        combined_expected.1,
    );
    assert_pending(
        &no_alias,
        1,
        1,
        separate_capacity,
        separate_capacity,
        combined_expected.1,
    );
    assert_pending(&after_acquire, 0, 0, 0, 0, negotiated_expected.1);
    assert!(captured
        .pending
        .owners
        .iter()
        .all(|owner| owner.source == source
            && owner.target == append_target
            && owner.family == ConsensusRpcFamily::InstallSnapshot));
    assert!(captured
        .pending
        .owners
        .iter()
        .all(|pending| captured.current.groups.iter().all(|group| group
            .owners
            .iter()
            .all(|negotiated| pending.call_id != negotiated.call_id))));
}
