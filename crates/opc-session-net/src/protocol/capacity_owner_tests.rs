//! Independent inspection of the real serializer owners, private to unit tests.

use super::*;
use crate::consensus::capacity_observation::{
    scope,
    tests::{capture_frame_owners, FrameOwnerCheck},
    BufferTotals, ConsensusBufferObservation,
};
use opc_consensus::{ConsensusNodeId, ConsensusRpcFamily};
use std::sync::Arc;
use std::time::Duration;

struct InspectedFrame {
    chunk_count: usize,
    descriptor_slots: usize,
    check: FrameOwnerCheck,
}

fn inspect_live_frame(
    observation: &ConsensusBufferObservation,
    payload: &Vec<u8>,
    frame: &EncodedFrame,
) -> InspectedFrame {
    assert!(
        !frame.chunks.is_empty(),
        "fixture must own real encoded chunks"
    );
    // Inspect each actual Box. This copies only address/extent metadata, never
    // encoded storage, and does not consult the observation registry or constants.
    let chunks: Vec<_> = frame
        .chunks
        .iter()
        .map(|chunk| {
            assert!(!chunk.bytes.is_empty());
            (chunk.bytes.as_ptr() as usize, chunk.bytes.len())
        })
        .collect();
    let descriptor_slots = frame.chunks.capacity();
    let descriptor = (
        frame.chunks.as_ptr() as usize,
        descriptor_slots * std::mem::size_of_val(&frame.chunks[0]),
    );
    assert!(descriptor_slots >= frame.chunks.len());
    let chunk_count = chunks.len();
    let check = capture_frame_owners(observation, payload, descriptor, chunks);
    InspectedFrame {
        chunk_count,
        descriptor_slots,
        check,
    }
}

#[tokio::test]
async fn serialized_frame_has_exact_live_owner_attribution() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let mut payload = vec![0xA5_u8; 131_073];
    let original = serde_json::to_vec(&payload).unwrap();
    payload.reserve_exact(65_537);
    assert!(payload.capacity() > payload.len());
    assert_eq!(serde_json::to_vec(&payload).unwrap(), original);
    let owner = observation
        .observe_call(
            ConsensusNodeId::new(1).unwrap(),
            ConsensusNodeId::new(2).unwrap(),
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let inspected = scope(Some(&owner), async {
        let frame = encode_frame_bounded(
            &payload,
            1_048_576,
            EncodingControl {
                deadline: Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                cancellation: &NEVER_CANCELLED,
            },
        )
        .unwrap();
        // Compare wire bytes directly through the original chunks; no cloned
        // frame is mistaken for the observed owner's backing.
        assert_eq!(frame.encoded_len, original.len());
        let mut offset = 0;
        for chunk in &frame.chunks {
            let end = offset + chunk.initialized;
            assert_eq!(chunk.initialized_bytes(), &original[offset..end]);
            offset = end;
        }
        assert_eq!(offset, original.len());
        let actual = inspect_live_frame(&observation, &payload, &frame);
        assert!(
            actual.chunk_count > 1,
            "fixture exercises distinct real boxed owners"
        );
        drop(frame);
        let after_frame = observation.snapshot();
        assert_eq!(after_frame.live.frame_allocations, 0);
        assert_eq!(after_frame.live.frame_bytes, 0);
        assert_eq!(after_frame.live.calls, 1);
        actual
    })
    .await;
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
    println!(
        "CONFIG_CAPACITY_EXACT_FRAME_LIFECYCLE wire_bytes=true frame_drained=true rpc_drained=true"
    );
    inspected.check.assert_exact();
}

#[tokio::test]
async fn descriptor_growth_tracks_actual_backing_and_spare_slots() {
    let observation = Arc::new(ConsensusBufferObservation::default());
    let mut payload = vec![7_u8; 257];
    let original = serde_json::to_vec(&payload).unwrap();
    payload.reserve_exact(513);
    assert!(payload.capacity() > payload.len());
    assert_eq!(serde_json::to_vec(&payload).unwrap(), original);
    let owner = observation
        .observe_call(
            ConsensusNodeId::new(1).unwrap(),
            ConsensusNodeId::new(2).unwrap(),
            ConsensusRpcFamily::InstallSnapshot,
            &payload,
        )
        .unwrap();
    let checks = scope(Some(&owner), async {
        let mut buffer = BoundedFrameBuffer::new(
            1_048_576,
            EncodingControl {
                deadline: Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                cancellation: &NEVER_CANCELLED,
            },
        );
        let mut previous_slots = 0;
        let mut grew_existing_backing = false;
        let mut saw_spare_slots = false;
        let mut checks = Vec::new();
        // Advance using real remaining space, without assuming initial/chunk
        // size, descriptor growth factor, element layout or allocator rounding.
        for _ in 0..32 {
            let remaining = buffer
                .frame
                .chunks
                .last()
                .map_or(0, |chunk| chunk.bytes.len() - chunk.initialized);
            let input = vec![b'7'; remaining + 1];
            std::io::Write::write_all(&mut buffer, &input).unwrap();
            let actual = inspect_live_frame(&observation, &payload, &buffer.frame);
            grew_existing_backing |=
                previous_slots != 0 && actual.descriptor_slots > previous_slots;
            saw_spare_slots |= actual.descriptor_slots > actual.chunk_count;
            previous_slots = actual.descriptor_slots;
            checks.push(actual.check);
            if grew_existing_backing && saw_spare_slots {
                break;
            }
        }
        assert!(
            grew_existing_backing,
            "fixture must observe descriptor backing growth"
        );
        assert!(
            saw_spare_slots,
            "fixture must own uninitialized descriptor slots"
        );
        // A rejected write leaves the already-owned frame available for direct
        // inspection. Its original bound is unchanged; no new chunk is admitted.
        let before_error = inspect_live_frame(&observation, &payload, &buffer.frame);
        let over_limit = vec![b'8'; buffer.max_frame_size - buffer.frame.encoded_len + 1];
        let error = std::io::Write::write_all(&mut buffer, &over_limit).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let after_error = inspect_live_frame(&observation, &payload, &buffer.frame);
        assert_eq!(after_error.chunk_count, before_error.chunk_count);
        assert_eq!(after_error.descriptor_slots, before_error.descriptor_slots);
        checks.push(before_error.check);
        checks.push(after_error.check);
        drop(buffer);
        let drained_frame = observation.snapshot();
        assert_eq!(drained_frame.live.frame_allocations, 0);
        assert_eq!(drained_frame.live.frame_bytes, 0);
        assert_eq!(drained_frame.live.calls, 1);
        checks
    })
    .await;
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
    println!("CONFIG_CAPACITY_DESCRIPTOR_GROWTH_LIFECYCLE growth=true spare_slots=true rejection=true frame_drained=true rpc_drained=true");
    for check in checks {
        check.assert_exact();
    }
}
