//! Actual serializer ownership and cancellation, independent of native setup.

use super::*;
use crate::protocol::write_frame_bounded_until;
use std::time::Duration;

fn payload_with_spare(value: u8, len: usize, spare: usize) -> Vec<u8> {
    let mut payload = vec![value; len];
    let original = serde_json::to_vec(&payload).unwrap();
    payload.reserve_exact(spare);
    assert!(
        payload.capacity() > payload.len(),
        "fixture owns genuine spare capacity"
    );
    assert_eq!(
        serde_json::to_vec(&payload).unwrap(),
        original,
        "spare backing does not change the original wire bytes"
    );
    payload
}

/// Numeric capture from one instant when the real frame is still borrowed.
/// No payload, frame, prepared owner or storage backend is retained here.
pub(crate) struct FrameOwnerCheck {
    calls: usize,
    registered_payload: Option<(usize, usize)>,
    registered_frame: bool,
    registered_descriptor: Option<(usize, usize)>,
    registered_chunks: BTreeMap<usize, usize>,
    reported: BufferTotals,
    actual_payload: (usize, usize),
    actual_descriptor: (usize, usize),
    actual_chunks: Vec<(usize, usize)>,
}

impl FrameOwnerCheck {
    /// Check captured attribution after wire, rejection and drain oracles finish.
    pub(crate) fn assert_exact(self) {
        assert_eq!(self.calls, 1, "one independently inspected call");
        let payload = self
            .registered_payload
            .expect("original borrowed call registration");
        assert!(
            payload.0 == self.actual_payload.0,
            "CONFIG_CAPACITY_RPC_IDENTITY_RED: exact borrowed request allocation"
        );
        assert_eq!(
            payload.1, self.actual_payload.1,
            "CONFIG_CAPACITY_RPC_CAPACITY_RED: count the borrowed Vec's real backing"
        );
        assert!(
            self.registered_frame,
            "CONFIG_CAPACITY_FRAME_OWNER_RED: original frame registration was live"
        );
        let descriptor = self
            .registered_descriptor
            .expect("CONFIG_CAPACITY_DESCRIPTOR_OWNER_RED: real descriptor backing is registered");
        assert!(
            descriptor.0 == self.actual_descriptor.0,
            "CONFIG_CAPACITY_DESCRIPTOR_IDENTITY_RED: exact live descriptor allocation"
        );
        assert_eq!(
            descriptor.1, self.actual_descriptor.1,
            "CONFIG_CAPACITY_DESCRIPTOR_CAPACITY_RED: include actual Vec spare slots"
        );
        assert_eq!(
            self.registered_chunks.len(),
            self.actual_chunks.len(),
            "CONFIG_CAPACITY_CHUNK_COUNT_RED: register every actual Box exactly once"
        );
        for (address, bytes) in &self.actual_chunks {
            assert_eq!(
                self.registered_chunks.get(address),
                Some(bytes),
                "CONFIG_CAPACITY_CHUNK_OWNER_RED: exact live boxed allocation extent"
            );
        }
        let mut identities = std::collections::BTreeSet::new();
        identities.insert(self.actual_descriptor.0);
        for (address, _) in &self.actual_chunks {
            identities.insert(*address);
        }
        assert_eq!(
            identities.len(),
            self.actual_chunks.len() + 1,
            "actual descriptor backing and nonempty Boxes have distinct identities"
        );
        let chunk_bytes: usize = self.actual_chunks.iter().map(|(_, bytes)| bytes).sum();
        assert_eq!(
            self.reported.frame_allocations,
            self.actual_chunks.len() + 1,
            "CONFIG_CAPACITY_FRAME_OWNER_RED: exact independently inspected allocation count"
        );
        assert_eq!(
            self.reported.frame_bytes,
            chunk_bytes + self.actual_descriptor.1,
            "CONFIG_CAPACITY_FRAME_OWNER_RED: exact independently inspected allocation extents"
        );
        assert_eq!(
            self.reported.rpc_bytes, self.actual_payload.1,
            "CONFIG_CAPACITY_RPC_CAPACITY_RED: census preserves actual spare backing"
        );
    }
}

/// Capture observations beside independently borrowed real frame owners.
///
/// Called only by private protocol unit tests while the actual EncodedFrame is
/// alive. Expected addresses and extents come from that frame's Vec and Boxes,
/// never from registry totals, encoding length, or an assumed chunk policy.
/// Only metadata is copied so checks can follow actual destruction and drains.
pub(crate) fn capture_frame_owners(
    observation: &ConsensusBufferObservation,
    payload: &Vec<u8>,
    descriptor: (usize, usize),
    chunks: Vec<(usize, usize)>,
) -> FrameOwnerCheck {
    let state = observation.state();
    let call = state.calls.values().next();
    let frame = call.and_then(|call| call.frame.as_ref());
    FrameOwnerCheck {
        calls: state.calls.len(),
        registered_payload: call.map(|call| (call.payload.address, call.payload.bytes)),
        registered_frame: frame.is_some(),
        registered_descriptor: frame
            .and_then(|frame| frame.descriptor)
            .map(|allocation| (allocation.address, allocation.bytes)),
        registered_chunks: frame.map_or_else(BTreeMap::new, |frame| frame.chunks.clone()),
        reported: state.snapshot.live,
        actual_payload: (payload.as_ptr() as usize, payload.capacity()),
        actual_descriptor: descriptor,
        actual_chunks: chunks,
    }
}

#[tokio::test]
async fn allocated_frame_and_borrowed_payload_drain_on_cancel() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let source = ConsensusNodeId::new(1).unwrap();
    let target = ConsensusNodeId::new(2).unwrap();
    observation.hold_snapshot_writes(target);
    let task_observation = observation.clone();
    let payload = payload_with_spare(255, 131_072, 65_536);
    let expected_capacity = payload.capacity();
    let task = tokio::spawn(async move {
        let owner = task_observation
            .observe_call(
                source,
                target,
                ConsensusRpcFamily::InstallSnapshot,
                &payload,
            )
            .unwrap();
        let (mut writer, _reader) = tokio::io::duplex(1);
        scope(
            Some(&owner),
            write_frame_bounded_until(
                &mut writer,
                &payload,
                1_048_576,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ),
        )
        .await
    });
    tokio::time::timeout(
        Duration::from_secs(1),
        observation.wait_for_snapshot_write(target),
    )
    .await
    .expect("actual encoded snapshot-family frame reaches write boundary");
    let live = observation.snapshot();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let drained = observation.snapshot();
    assert_eq!(drained.live, BufferTotals::default());
    assert_eq!(live.live.calls, 1);
    assert_eq!(
        live.live.rpc_bytes, expected_capacity,
        "CONFIG_CAPACITY_RPC_CAPACITY_RED: live borrowed RPC includes actual spare capacity"
    );
    assert_eq!(live.live.ready_frames, 1);
    assert!(
        live.live.frame_allocations > 1,
        "CONFIG_CAPACITY_FRAME_OWNER_RED: observe real boxed chunks and descriptor backing"
    );
    assert!(
        live.live.frame_bytes >= 524_289,
        "CONFIG_CAPACITY_FRAME_OWNER_RED: decimal JSON expansion is really retained"
    );
}

#[tokio::test]
async fn actual_frame_bytes_preserve_original_serde_and_drain_after_write() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let payload = payload_with_spare(0xA5, 16_385, 8_192);
    let original = serde_json::to_vec(&payload).unwrap();
    let owner = observation
        .observe_call(
            ConsensusNodeId::new(1).unwrap(),
            ConsensusNodeId::new(2).unwrap(),
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let mut output = Vec::new();
    scope(
        Some(&owner),
        write_frame_bounded_until(
            &mut output,
            &payload,
            1_048_576,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ),
    )
    .await
    .unwrap();
    assert_eq!(&output[..4], &(original.len() as u32).to_be_bytes());
    assert_eq!(&output[4..], original);
    let after_write = observation.snapshot();
    assert_eq!(after_write.live.rpc_bytes, payload.capacity());
    assert_eq!(after_write.live.frame_bytes, 0);
    assert!(
        after_write.peak.frame_bytes >= original.len(),
        "CONFIG_CAPACITY_FRAME_OWNER_RED: retain actual frame capacities, not a declared limit"
    );
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
}

#[tokio::test]
async fn rejected_encoding_drops_real_chunks_before_returning_error() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let payload = payload_with_spare(255, 4_096, 4_096);
    let owner = observation
        .observe_call(
            ConsensusNodeId::new(1).unwrap(),
            ConsensusNodeId::new(2).unwrap(),
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let mut output = Vec::new();
    let result = scope(
        Some(&owner),
        write_frame_bounded_until(
            &mut output,
            &payload,
            128,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ),
    )
    .await;
    assert!(matches!(
        result,
        Err(crate::error::ProtocolError::FrameTooLarge(_))
    ));
    assert!(
        output.is_empty(),
        "rejection stays before the first frame byte"
    );
    let after_error = observation.snapshot();
    assert_eq!(after_error.live.rpc_bytes, payload.capacity());
    assert_eq!(after_error.live.frame_bytes, 0);
    assert!(
        after_error.peak.frame_bytes > 0,
        "CONFIG_CAPACITY_FRAME_OWNER_RED: observe actual partial encoding owners"
    );
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
}

#[test]
fn payload_aliases_share_identity_and_equal_contents_do_not() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let payload = payload_with_spare(1, 4_096, 4_096);
    let independent = payload_with_spare(1, payload.len(), payload.capacity());
    assert_eq!(
        payload, independent,
        "equal bytes, independent real allocations"
    );
    assert!(payload.as_ptr() != independent.as_ptr());
    assert!(independent.capacity() > payload.capacity());
    let source = ConsensusNodeId::new(1).unwrap();
    let target = ConsensusNodeId::new(2).unwrap();
    let first = observation
        .observe_call(
            source,
            target,
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let alias = observation
        .observe_call(
            source,
            target,
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let distinct = observation
        .observe_call(
            source,
            target,
            ConsensusRpcFamily::InstallSnapshot,
            &independent,
        )
        .unwrap();
    let shared = observation.snapshot();
    assert_eq!(shared.live.calls, 3);
    assert_eq!(
        shared.live.rpc_bytes,
        payload.capacity() + independent.capacity(),
        "CONFIG_CAPACITY_RPC_CAPACITY_RED: distinct backing plus one shared identity"
    );
    drop(first);
    assert_eq!(
        observation.snapshot().live.rpc_bytes,
        payload.capacity() + independent.capacity(),
        "CONFIG_CAPACITY_RPC_CAPACITY_RED: dropping one alias cannot free its shared backing"
    );
    drop(alias);
    assert_eq!(
        observation.snapshot().live.rpc_bytes,
        independent.capacity()
    );
    drop(distinct);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
}
