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

#[derive(Clone, Copy)]
struct CensusCallSpec {
    source: ConsensusNodeId,
    target: ConsensusNodeId,
    family: ConsensusRpcFamily,
    generation: u64,
    selected_append: bool,
    snapshot_data_bytes: usize,
}

struct CensusFrame<'a> {
    // Deregister the actual frame before its buffers, then release the RPC borrow.
    frame: EncodedFrame,
    _owner: crate::consensus::capacity_observation::CallOwner<'a>,
}

impl CensusFrame<'_> {
    async fn write<W: tokio::io::AsyncWrite + Unpin>(
        self,
        mut writer: W,
    ) -> Result<W, ProtocolError> {
        let write = async {
            self.frame
                .observation
                .as_ref()
                .unwrap()
                .ready_and_wait()
                .await;
            writer
                .write_all(&u32::try_from(self.frame.encoded_len).unwrap().to_be_bytes())
                .await?;
            for chunk in &self.frame.chunks {
                writer.write_all(chunk.initialized_bytes()).await?;
            }
            writer.flush().await
        };
        tokio::time::timeout(Duration::from_secs(2), write)
            .await
            .expect("real test frame write remains bounded")
            .map_err(ProtocolError::Io)?;
        Ok(writer)
    }
}

async fn census_frame<'a>(
    observation: &Arc<ConsensusBufferObservation>,
    payload: &'a Vec<u8>,
    spec: CensusCallSpec,
) -> (
    CensusFrame<'a>,
    crate::consensus::capacity_observation::tests::ActualTransportOwner,
) {
    use crate::consensus::capacity_observation::{
        scope_typed_transport, tests::ActualTransportOwner,
    };
    let owner = scope_typed_transport(
        spec.selected_append,
        spec.snapshot_data_bytes,
        spec.generation,
        async {
            observation
                .observe_call(spec.source, spec.target, spec.family, payload)
                .unwrap()
        },
    )
    .await;
    let frame = scope(Some(&owner), async {
        encode_frame_bounded(
            payload,
            4 * 1_048_576,
            EncodingControl {
                deadline: Some(tokio::time::Instant::now() + Duration::from_secs(2)),
                cancellation: &NEVER_CANCELLED,
            },
        )
        .unwrap()
    })
    .await;
    // Enumerate original allocated owners directly, not registry summaries or
    // a second encoding. Only numeric identities/extents survive the capture.
    let mut allocations: Vec<_> = frame
        .chunks
        .iter()
        .map(|chunk| (chunk.bytes.as_ptr() as usize, chunk.bytes.len()))
        .collect();
    allocations.push((
        frame.chunks.as_ptr() as usize,
        frame.chunks.capacity() * std::mem::size_of::<EncodedFrameChunk>(),
    ));
    let actual = ActualTransportOwner {
        source: spec.source,
        target: spec.target,
        family: spec.family,
        generation: spec.generation,
        selected_append: spec.selected_append,
        payload: (payload.as_ptr() as usize, payload.capacity()),
        frame: allocations,
        ready: true,
    };
    (
        CensusFrame {
            frame,
            _owner: owner,
        },
        actual,
    )
}

#[tokio::test]
async fn current_native_census_counts_live_aliases_and_removes_cancelled_owners() {
    use crate::consensus::capacity_observation::tests::{
        assert_current_census, ActualTransportOwner,
    };
    use std::future::Future;
    use std::task::{Context, Waker};
    use tokio::io::AsyncReadExt;

    let observation = Arc::new(ConsensusBufferObservation::default());
    let node = |id| ConsensusNodeId::new(id).unwrap();
    let source = node(1);
    let snapshot_target = node(2);
    let append_target = node(3);
    let mut shared = vec![0_u8; 1_048_577];
    shared.reserve_exact(8_193);
    let mut distinct = vec![0_u8; shared.len()];
    distinct.reserve_exact(16_385);
    assert_eq!(shared, distinct);
    assert_ne!(shared.as_ptr(), distinct.as_ptr());
    let mut snapshot = vec![7_u8; 1_025];
    snapshot.reserve_exact(1_027);
    let snapshot_input = vec![8_u8; 257];
    observation.hold_snapshot_writes(snapshot_target);
    observation.hold_native_append_writes(source, append_target);

    let append_spec = CensusCallSpec {
        source,
        target: append_target,
        family: ConsensusRpcFamily::AppendEntries,
        generation: 12,
        selected_append: true,
        snapshot_data_bytes: 0,
    };
    let (append, actual_append) = census_frame(&observation, &shared, append_spec).await;
    let (snap, actual_snapshot) = census_frame(
        &observation,
        &snapshot,
        CensusCallSpec {
            source,
            target: snapshot_target,
            family: ConsensusRpcFamily::InstallSnapshot,
            generation: 11,
            selected_append: false,
            snapshot_data_bytes: snapshot_input.capacity(),
        },
    )
    .await;
    let (alias, actual_alias) = census_frame(
        &observation,
        &shared,
        CensusCallSpec {
            target: node(4),
            generation: 13,
            ..append_spec
        },
    )
    .await;
    let (other, actual_other) = census_frame(
        &observation,
        &distinct,
        CensusCallSpec {
            target: node(5),
            generation: 0,
            selected_append: false,
            ..append_spec
        },
    )
    .await;
    let (foreign, actual_foreign) = census_frame(
        &observation,
        &shared,
        CensusCallSpec {
            source: node(9),
            target: node(6),
            family: ConsensusRpcFamily::InstallSnapshot,
            generation: 21,
            selected_append: false,
            snapshot_data_bytes: snapshot_input.capacity(),
        },
    )
    .await;
    let rpc_only = observation
        .observe_call(
            node(9),
            node(7),
            ConsensusRpcFamily::InstallSnapshot,
            &snapshot,
        )
        .unwrap();
    let actual_rpc_only = ActualTransportOwner {
        source: node(9),
        target: node(7),
        family: ConsensusRpcFamily::InstallSnapshot,
        generation: 0,
        selected_append: false,
        payload: (snapshot.as_ptr() as usize, snapshot.capacity()),
        frame: Vec::new(),
        ready: false,
    };
    let expected = vec![
        actual_append,
        actual_snapshot,
        actual_alias,
        actual_other,
        actual_foreign,
        actual_rpc_only,
    ];

    // Backpressure is real IO, not an extra observer gate. The normal minority
    // pair releases quorum traffic; the three duplex writers reach actual bytes.
    let (alias_writer, mut alias_reader) = tokio::io::duplex(65_536);
    let (other_writer, mut other_reader) = tokio::io::duplex(65_536);
    let (foreign_writer, mut foreign_reader) = tokio::io::duplex(65_536);
    let mut append = Box::pin(append.write(Vec::new()));
    let mut snap = Box::pin(snap.write(Vec::new()));
    let mut alias = Box::pin(alias.write(alias_writer));
    let mut other = Box::pin(other.write(other_writer));
    let mut foreign = Box::pin(foreign.write(foreign_writer));
    let mut context = Context::from_waker(Waker::noop());
    assert!(snap.as_mut().poll(&mut context).is_pending());
    assert!(append.as_mut().poll(&mut context).is_pending());
    assert!(alias.as_mut().poll(&mut context).is_pending());
    assert!(other.as_mut().poll(&mut context).is_pending());
    assert!(foreign.as_mut().poll(&mut context).is_pending());
    let all_current = observation.capture_native_overlap_and_release(source);

    // Drop one real in-progress writer plus an RPC-only alias. Other aliases
    // remain borrowed. A fresh same-instant capture must exclude both owners.
    drop(alias);
    drop(rpc_only);
    observation.hold_snapshot_writes(snapshot_target);
    observation.hold_native_append_writes(source, append_target);
    let after_cancel = observation.capture_native_overlap_and_release(source);
    let mut cancelled_wire = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        alias_reader.read_to_end(&mut cancelled_wire),
    )
    .await
    .unwrap()
    .unwrap();
    let append_wire = append.await.unwrap();
    let snapshot_wire = snap.await.unwrap();
    let mut other_wire = Vec::new();
    let mut foreign_wire = Vec::new();
    let (_, other_read, _, foreign_read) = tokio::join!(
        async {
            drop(other.await.unwrap());
        },
        other_reader.read_to_end(&mut other_wire),
        async {
            drop(foreign.await.unwrap());
        },
        foreign_reader.read_to_end(&mut foreign_wire),
    );
    other_read.unwrap();
    foreign_read.unwrap();

    for (wire, payload) in [
        (&append_wire, &shared),
        (&snapshot_wire, &snapshot),
        (&other_wire, &distinct),
        (&foreign_wire, &shared),
    ] {
        let original = serde_json::to_vec(payload).unwrap();
        assert_eq!(
            &wire[..4],
            &u32::try_from(original.len()).unwrap().to_be_bytes()
        );
        assert_eq!(&wire[4..], original);
    }
    assert!(cancelled_wire.len() > 4 && cancelled_wire.len() < append_wire.len());
    assert_eq!(cancelled_wire, append_wire[..cancelled_wire.len()]);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
    drop(shared);
    drop(distinct);
    drop(snapshot);
    drop(snapshot_input);
    println!("CONFIG_CAPACITY_CURRENT_CENSUS_LIFECYCLE full_writes=4 partial_cancel=1 rpc_only_drop=1 drained=true native_operation=false");

    let captured =
        all_current.expect("original selected pair existed beside all additional owners");
    assert_current_census(&captured, &expected, [0, 1]);
    assert_eq!(captured.current.total.calls, 6);
    assert_eq!(captured.current.total.ready_frames, 5);
    assert_eq!(captured.current.groups.len(), 3);
    assert_eq!(captured.current.additional.calls, 4);
    // Only the distinct additional Vec adds RPC capacity: two aliases of the
    // selected append and one alias of the snapshot never duplicate that charge.
    assert_eq!(captured.current.additional.rpc_bytes, expected[3].payload.1);
    let after_cancel = after_cancel.expect("original pair survives unrelated cancellation");
    let remaining: Vec<_> = expected
        .into_iter()
        .enumerate()
        .filter_map(|(index, owner)| (!matches!(index, 2 | 5)).then_some(owner))
        .collect();
    assert_current_census(&after_cancel, &remaining, [0, 1]);
    assert_eq!(after_cancel.current.total.calls, 4);
    assert_eq!(after_cancel.current.total.ready_frames, 4);
    assert_eq!(after_cancel.current.additional.calls, 2);
    assert_eq!(
        after_cancel.current.total.rpc_bytes,
        captured.current.total.rpc_bytes
    );
    assert!(
        after_cancel.current.total.frame_bytes < captured.current.total.frame_bytes,
        "CONFIG_CAPACITY_CURRENT_DROP_RED: cancelled frames no longer belong to the current census"
    );
    println!("CONFIG_CAPACITY_CURRENT_CENSUS_PASS before_calls=6 after_calls=4 distinct_sources=2 groups=3 full_memory_bound=false");
}
