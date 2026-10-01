//! Work bounds on the actual framed encoder, with an independent JSON oracle.

use super::*;
use crate::consensus::capacity_observation::{scope, BufferTotals, ConsensusBufferObservation};
use std::cell::Cell;
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Copy, Default)]
struct Work {
    frames: usize,
    control_checks: usize,
    fragment_writes: usize,
    encoded_bytes: usize,
    retained_bytes: usize,
    chunks: usize,
    descriptor_bytes: usize,
}

thread_local! {
    static OBSERVED_WORK: Cell<Option<Work>> = const { Cell::new(None) };
}

// Called once per successfully encoded real frame. The hot-loop count itself
// is a test-only scalar in that same EncodedFrame, never a clock/atomic/lock.
pub(super) fn record_frame_work(frame: &EncodedFrame) {
    OBSERVED_WORK.with(|slot| {
        if let Some(mut work) = slot.get() {
            work.frames += 1;
            work.control_checks += frame.encoding_control_checks;
            work.fragment_writes += frame.encoding_fragment_writes;
            work.encoded_bytes += frame.encoded_len;
            work.retained_bytes += frame.retained_byte_capacity;
            work.chunks += frame.chunks.len();
            work.descriptor_bytes +=
                frame.chunks.capacity() * std::mem::size_of::<EncodedFrameChunk>();
            slot.set(Some(work));
        }
    });
}

struct WorkCount(bool);

impl WorkCount {
    fn start() -> Self {
        OBSERVED_WORK.with(|slot| assert!(slot.replace(Some(Work::default())).is_none()));
        Self(true)
    }

    fn finish(mut self) -> Work {
        self.0 = false;
        OBSERVED_WORK.with(|slot| slot.take().expect("armed encoder work count"))
    }
}

impl Drop for WorkCount {
    fn drop(&mut self) {
        if self.0 {
            OBSERVED_WORK.with(|slot| slot.set(None));
        }
    }
}

fn normal_call(payload_bytes: usize) -> SessionConsensusTransportRequest {
    let cluster = opc_consensus::ConsensusClusterId::new("batch-control").unwrap();
    let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap();
    let identity = opc_consensus::ConsensusIdentity::new(
        cluster,
        opc_consensus::derive_configuration_id(cluster, epoch, &[[9; 32]]),
        epoch,
    );
    let sender = opc_consensus::derive_node_id(cluster, b"batch-replica").unwrap();
    let payload = (0_u8..=255).cycle().take(payload_bytes).collect();
    let request = SessionConsensusWireRequest::try_new(
        identity,
        sender,
        ConsensusRpcFamily::AppendEntries,
        payload,
    )
    .unwrap();
    SessionConsensusTransportRequest::from_wire_call(uuid::Uuid::nil(), request).unwrap()
}

async fn check_normal_call_work(payload_bytes: usize) {
    let frame = normal_call(payload_bytes);
    // Independent Vec sink: does not call the bounded encoder or its adapter.
    let original = serde_json::to_vec(&frame).unwrap();
    let SessionConsensusTransportRequest::Call { request, .. } = &frame else {
        panic!("exercise the original normal Call representation");
    };
    let observation = Arc::new(ConsensusBufferObservation::default());
    let owner = observation
        .observe_call(
            request.sender,
            opc_consensus::ConsensusNodeId::new(2).unwrap(),
            request.family,
            &request.payload,
        )
        .expect("real large AppendEntries owner");
    let counter = WorkCount::start();
    let mut output = Vec::new();
    scope(Some(&owner), async {
        write_frame_bounded_until(
            &mut output,
            &frame,
            original.len(),
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("real framing inside the original AppendEntries deadline");
    })
    .await;
    let work = counter.finish();
    assert_eq!(work.frames, 1, "observe the frame actually sent");
    assert_eq!(work.encoded_bytes, original.len());
    assert_eq!(
        work.retained_bytes,
        original.len(),
        "exact encoded storage ceiling"
    );
    assert_eq!(
        &output[..4],
        &u32::try_from(original.len()).unwrap().to_be_bytes(),
    );
    assert_eq!(&output[4..], original);
    let mut reader = output.as_slice();
    let decoded: SessionConsensusTransportRequest = read_frame(&mut reader, original.len())
        .await
        .expect("decode the actual framed bytes");
    assert!(
        decoded == frame,
        "every synthetic byte survives the original wire format"
    );
    let after_frame = observation.snapshot();
    assert_eq!(after_frame.live.frame_allocations, 0);
    assert_eq!(after_frame.live.frame_bytes, 0);
    assert_eq!(after_frame.live.calls, 1);
    assert_eq!(after_frame.peak.ready_frames, 1);
    assert_eq!(after_frame.peak.frame_allocations, work.chunks + 1);
    assert_eq!(
        after_frame.peak.frame_bytes,
        work.retained_bytes + work.descriptor_bytes
    );
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
    println!(
        "CONFIG_CAPACITY_BATCH_LIFECYCLE payload_bytes={payload_bytes} wire_bytes=true decoded=true exact_limit=true frame_drained=true rpc_drained=true checks={}",
        work.control_checks,
    );
    // Work contract independent of the adapter's constants: at most one sink
    // probe per 512 output bytes, plus real chunk crossings and fixed headroom.
    // The current generic per-fragment path exceeds this by orders of magnitude.
    let maximum_checks = original.len().div_ceil(512) + work.chunks + 8;
    assert!(
        work.control_checks <= maximum_checks,
        "CONFIG_CAPACITY_BATCH_WORK_RED actual={} maximum={maximum_checks}",
        work.control_checks,
    );
}

#[tokio::test]
async fn normal_call_ordinary_payload_batches_control_work() {
    check_normal_call_work(1_573_769).await;
}

#[tokio::test]
async fn normal_call_audited_payload_batches_control_work() {
    check_normal_call_work(1_880_759).await;
}

#[tokio::test]
async fn batched_call_preserves_exact_and_one_over_limits_for_every_byte() {
    for payload_bytes in [0, 1, 255, 256, 1_023, 1_024, 1_025, 8_191, 8_192, 8_193] {
        let frame = normal_call(payload_bytes);
        let original = serde_json::to_vec(&frame).unwrap();
        let mut output = Vec::new();
        write_frame_bounded_until(
            &mut output,
            &frame,
            original.len(),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("exact limit");
        assert_eq!(
            &output[..4],
            &u32::try_from(original.len()).unwrap().to_be_bytes()
        );
        assert_eq!(&output[4..], original);
        for limit in [0, original.len() - 1] {
            output.clear();
            let progress = FrameWriteProgress::new();
            let error = write_frame_bounded_until_classified_with_progress(
                &mut output,
                &frame,
                limit,
                tokio::time::Instant::now() + Duration::from_secs(1),
                &progress,
            )
            .await
            .expect_err("oversize must fail before any prefix");
            assert!(
                matches!(error, FrameWriteError::BeforeWrite(ProtocolError::FrameTooLarge(n)) if n > limit)
            );
            assert!(output.is_empty());
            assert!(!progress.accepted_any());
        }
    }
}

enum MidAction<'a> {
    Cancel(&'a AtomicBool),
    Expire,
    SerializationError,
}

struct InterruptWithPendingBytes<'a> {
    produced: &'a AtomicUsize,
    action: MidAction<'a>,
}

impl Serialize for InterruptWithPendingBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut sequence = serializer.serialize_seq(Some(32_768))?;
        for index in 0..32_768 {
            if index == 128 {
                match &self.action {
                    MidAction::Cancel(cancellation) => cancellation.store(true, Ordering::Release),
                    MidAction::Expire => {
                        // Keep the original 1 ms deadline, but arm real time
                        // only after pending bytes exist. Scheduler delay
                        // before this point cannot expire the fixture early.
                        tokio::time::resume();
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    MidAction::SerializationError => {
                        return Err(S::Error::custom("synthetic stop"));
                    }
                }
            }
            sequence.serialize_element(&7_u8)?;
            self.produced.fetch_add(1, Ordering::Relaxed);
        }
        sequence.end()
    }
}

async fn interrupted_pending_bytes(action: MidAction<'_>, expected: Option<std::io::ErrorKind>) {
    let cancellation = match &action {
        MidAction::Cancel(cancellation) => *cancellation,
        _ => &NEVER_CANCELLED,
    };
    let duration = if matches!(&action, MidAction::Expire) {
        Duration::from_millis(1)
    } else {
        Duration::from_secs(1)
    };
    let produced = AtomicUsize::new(0);
    let value = InterruptWithPendingBytes {
        produced: &produced,
        action,
    };
    let progress = FrameWriteProgress::new();
    let mut output = Vec::new();
    let error = write_frame_bounded_until_cancellable_classified_with_progress(
        &mut output,
        &value,
        MIN_NEGOTIATED_FRAME_SIZE,
        tokio::time::Instant::now() + duration,
        cancellation,
        &progress,
    )
    .await
    .expect_err("buffered bytes cannot cross the prefix boundary after interruption");
    match (expected, error) {
        (Some(expected), FrameWriteError::BeforeWrite(ProtocolError::Io(error))) => {
            assert_eq!(error.kind(), expected);
        }
        (None, FrameWriteError::BeforeWrite(ProtocolError::Serialization(_))) => {}
        _ => panic!("preserve the original pre-prefix error classification"),
    }
    let produced = produced.load(Ordering::Relaxed);
    assert!(
        produced >= 128,
        "interruption occurs with real pending serialized bytes"
    );
    assert!(
        produced <= 128 + 1_024,
        "control work stays bounded after interruption"
    );
    assert!(!progress.accepted_any());
    assert!(output.is_empty());
}

#[tokio::test]
async fn buffered_cancellation_stops_cooperatively_before_prefix() {
    let cancellation = AtomicBool::new(false);
    interrupted_pending_bytes(
        MidAction::Cancel(&cancellation),
        Some(std::io::ErrorKind::Interrupted),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn buffered_deadline_stops_cooperatively_before_prefix() {
    interrupted_pending_bytes(MidAction::Expire, Some(std::io::ErrorKind::TimedOut)).await;
}

#[tokio::test]
async fn serializer_error_does_not_flush_pending_bytes_to_transport() {
    interrupted_pending_bytes(MidAction::SerializationError, None).await;
}

#[test]
fn empty_callbacks_stop_cancelled_encoding_without_pending_bytes() {
    check_empty_callback_cancellation(false);
}

#[test]
fn empty_callbacks_stop_cancelled_encoding_with_pending_bytes() {
    check_empty_callback_cancellation(true);
}

fn check_empty_callback_cancellation(pending: bool) {
    let cancellation = AtomicBool::new(false);
    let control = EncodingControl {
        deadline: None,
        cancellation: &cancellation,
    };
    let mut sink = BoundedFrameBuffer::new(1_024, control);
    let mut fragments = FrameFragmentBuffer::new(&mut sink);
    if pending {
        assert_eq!(std::io::Write::write(&mut fragments, b"x").unwrap(), 1);
    }
    cancellation.store(true, Ordering::Release);
    // Direct Write::write is intentional: write_all skips empty slices.
    // This bound is the documented callback contract, independent of bytes.
    let stopped = (0..1_024).find_map(|_| std::io::Write::write(&mut fragments, &[]).err());
    assert!(
        matches!(stopped, Some(ref error) if error.kind() == std::io::ErrorKind::Other),
        "CONFIG_CAPACITY_EMPTY_CALLBACK_RED: empty callbacks must observe cancellation within 1024 writes"
    );
    // The private sink uses Other to avoid write_all retrying Interrupted.
    // Public Interrupted mapping is covered through the real framed writer.
    assert_eq!(sink.halted, Some(EncodingHalt::Cancelled));
    assert_eq!(sink.frame.encoded_len, 0);
    assert!(sink.frame.chunks.is_empty());
}

struct HaltThenSerializerError<'a> {
    cancellation: &'a AtomicBool,
    expire: bool,
    additional_fragment: bool,
    reached_halt: &'a AtomicBool,
}

impl Serialize for HaltThenSerializerError<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(&7_u8)?;
        self.reached_halt.store(true, Ordering::Release);
        if self.expire {
            tokio::time::resume();
            std::thread::sleep(Duration::from_millis(5));
        } else {
            self.cancellation.store(true, Ordering::Release);
        }
        if self.additional_fragment {
            sequence.serialize_element(&8_u8)?;
        }
        Err(S::Error::custom("synthetic error following the halt"))
    }
}

async fn assert_halt_before_serializer_error(expire: bool, additional_fragment: bool) {
    let cancellation = AtomicBool::new(false);
    let reached_halt = AtomicBool::new(false);
    let value = HaltThenSerializerError {
        cancellation: &cancellation,
        expire,
        additional_fragment,
        reached_halt: &reached_halt,
    };
    let duration = if expire {
        Duration::from_millis(1)
    } else {
        Duration::from_secs(1)
    };
    let mut output = Vec::new();
    let progress = FrameWriteProgress::new();
    let error = write_frame_bounded_until_cancellable_classified_with_progress(
        &mut output,
        &value,
        MIN_NEGOTIATED_FRAME_SIZE,
        tokio::time::Instant::now() + duration,
        &cancellation,
        &progress,
    )
    .await
    .expect_err("a halted failed serializer never writes a prefix");
    assert!(reached_halt.load(Ordering::Acquire));
    assert!(output.is_empty());
    assert!(!progress.accepted_any());
    let expected = if expire {
        std::io::ErrorKind::TimedOut
    } else {
        std::io::ErrorKind::Interrupted
    };
    assert!(
        matches!(error, FrameWriteError::BeforeWrite(ProtocolError::Io(ref error)) if error.kind() == expected),
        "CONFIG_CAPACITY_ERROR_HALT_RED: completion fence must report the halt before a custom serializer error; actual={error:?}"
    );
}

#[tokio::test]
async fn cancellation_then_additional_fragment_and_error_reports_halt() {
    assert_halt_before_serializer_error(false, true).await;
}

#[tokio::test(start_paused = true)]
async fn deadline_then_additional_fragment_and_error_reports_halt() {
    assert_halt_before_serializer_error(true, true).await;
}

// These two cases deliberately strengthen completion error precedence: even
// without another write, a failed serializer cannot mask cancellation/expiry.
#[tokio::test]
async fn cancellation_after_final_fragment_and_error_reports_halt() {
    assert_halt_before_serializer_error(false, false).await;
}

#[tokio::test(start_paused = true)]
async fn deadline_after_final_fragment_and_error_reports_halt() {
    assert_halt_before_serializer_error(true, false).await;
}

struct LatchedErrorThenSerializerError<'a> {
    cancellation: &'a AtomicBool,
    halt_first: bool,
}

impl Serialize for LatchedErrorThenSerializerError<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(&7_u8)?;
        self.cancellation.store(self.halt_first, Ordering::Release);
        let failed = sequence.serialize_element(&"x".repeat(2_048));
        assert!(failed.is_err(), "actual sink must latch the first error");
        // Deliberately change the signal after the sink has recorded its error.
        self.cancellation.store(!self.halt_first, Ordering::Release);
        Err(S::Error::custom("serializer discards the prior sink error"))
    }
}

async fn assert_latched_error_precedes_later_signal(halt_first: bool) {
    let cancellation = AtomicBool::new(false);
    let value = LatchedErrorThenSerializerError {
        cancellation: &cancellation,
        halt_first,
    };
    let mut output = Vec::new();
    let progress = FrameWriteProgress::new();
    let error = write_frame_bounded_until_cancellable_classified_with_progress(
        &mut output,
        &value,
        32,
        tokio::time::Instant::now() + Duration::from_secs(1),
        &cancellation,
        &progress,
    )
    .await
    .expect_err("latched sink error survives a serializer's custom error");
    assert!(output.is_empty());
    assert!(!progress.accepted_any());
    if halt_first {
        assert!(
            matches!(error, FrameWriteError::BeforeWrite(ProtocolError::Io(ref error))
            if error.kind() == std::io::ErrorKind::Interrupted)
        );
    } else {
        assert!(
            matches!(error, FrameWriteError::BeforeWrite(ProtocolError::FrameTooLarge(n)) if n > 32)
        );
    }
}

#[tokio::test]
async fn latched_cancellation_survives_signal_clear_and_serializer_error() {
    assert_latched_error_precedes_later_signal(true).await;
}

#[tokio::test]
async fn latched_oversize_precedes_later_cancellation_and_serializer_error() {
    assert_latched_error_precedes_later_signal(false).await;
}

#[path = "consensus_json_tests.rs"]
mod consensus_json_tests;
