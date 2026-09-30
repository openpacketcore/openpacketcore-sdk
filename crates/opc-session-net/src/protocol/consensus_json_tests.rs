//! Exact wire and effect-boundary controls for the real borrowed call writer.

use super::*;

async fn borrowed_call_work(payload_bytes: usize) {
    let frame = normal_call(payload_bytes);
    // The original owned DTO still uses its original derive and Vec encoding.
    let original = serde_json::to_vec(&frame).unwrap();
    let SessionConsensusTransportRequest::Call { request, .. } = &frame else {
        panic!("ordinary numeric-array envelope");
    };
    let observation = Arc::new(ConsensusBufferObservation::default());
    let owner = observation
        .observe_call(
            request.sender,
            opc_consensus::ConsensusNodeId::new(2).unwrap(),
            request.family,
            &request.payload,
        )
        .unwrap();
    let counter = WorkCount::start();
    let mut output = Vec::new();
    scope(Some(&owner), async {
        write_consensus_frame_bounded_until(
            &mut output,
            &frame,
            original.len(),
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .expect("original complete AppendEntries deadline");
    })
    .await;
    let work = counter.finish();
    assert_eq!(work.frames, 1);
    assert_eq!(work.encoded_bytes, original.len());
    assert_eq!(work.retained_bytes, original.len());
    assert_eq!(
        &output[..4],
        &u32::try_from(original.len()).unwrap().to_be_bytes(),
    );
    assert_eq!(&output[4..], original);
    let mut reader = output.as_slice();
    let decoded: SessionConsensusTransportRequest =
        read_frame(&mut reader, original.len()).await.unwrap();
    assert!(decoded == frame);
    let snapshot = observation.snapshot();
    assert_eq!(snapshot.live.frame_allocations, 0);
    assert_eq!(snapshot.live.frame_bytes, 0);
    assert_eq!(snapshot.live.calls, 1);
    assert_eq!(snapshot.peak.ready_frames, 1);
    assert_eq!(snapshot.peak.frame_allocations, work.chunks + 1);
    assert_eq!(
        snapshot.peak.frame_bytes,
        work.retained_bytes + work.descriptor_bytes
    );
    drop(owner);
    assert_eq!(observation.snapshot().live, BufferTotals::default());
    assert!(
        work.control_checks <= original.len().div_ceil(512) + work.chunks + 8,
        "bounded sink checks must survive numeric emission",
    );
    println!(
        "CONFIG_CAPACITY_NUMERIC_WIRE_LIFECYCLE payload={payload_bytes} exact_bytes=true decoded=true exact_limit=true frame_drained=true rpc_drained=true fragments={}",
        work.fragment_writes,
    );
    let maximum = original.len().div_ceil(512) + 256;
    assert!(
        work.fragment_writes <= maximum,
        "CONFIG_CAPACITY_NUMERIC_WIRE_WORK_RED: actual serializer writes={} maximum={maximum}, after complete wire and owner oracles",
        work.fragment_writes,
    );
}

#[tokio::test]
async fn ordinary_call_borrows_bytes_without_per_byte_serializer_dispatch() {
    borrowed_call_work(1_573_769).await;
}

#[tokio::test]
async fn audited_call_borrows_bytes_without_per_byte_serializer_dispatch() {
    borrowed_call_work(1_880_759).await;
}

#[tokio::test]
async fn borrowed_call_preserves_original_shapes_limits_and_every_byte() {
    let mut encoded_cases = 0;
    let mut rejected_cases = 0;
    for size in [0, 1, 255, 256, 1023, 1024, 1025, 8191, 8192, 8193] {
        let SessionConsensusTransportRequest::Call { request, .. } = normal_call(size) else {
            panic!("original ordinary fixture");
        };
        for family in [
            ConsensusRpcFamily::AppendEntries,
            ConsensusRpcFamily::Vote,
            ConsensusRpcFamily::InstallSnapshot,
            ConsensusRpcFamily::ForwardMutation,
            ConsensusRpcFamily::ReadBarrier,
            ConsensusRpcFamily::LeadershipTransfer,
            ConsensusRpcFamily::TopologyAdmissionBarrier,
            ConsensusRpcFamily::AppendEntriesRoster,
            ConsensusRpcFamily::ForwardRosterMutation,
        ] {
            let mut request = request.clone();
            request.family = family;
            let frame = SessionConsensusTransportRequest::from_wire_call(
                uuid::Uuid::from_u128(0x0b69_28ea_8df2_48c7_ae08_9857_c9ab_41ee),
                request,
            );
            if family == ConsensusRpcFamily::LeadershipTransfer && size > 1_024 {
                assert!(
                    matches!(frame, Err(SessionConsensusPeerError::Protocol)),
                    "preserve the original 1,024-byte leadership-transfer bound",
                );
                rejected_cases += 1;
                continue;
            }
            let frame = frame.expect("payload within the original family bound");
            let original = serde_json::to_vec(&frame).unwrap();
            let mut output = Vec::new();
            write_consensus_frame_bounded_until(
                &mut output,
                &frame,
                original.len(),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            assert_eq!(&output[4..], original);
            let mut reader = output.as_slice();
            let decoded: SessionConsensusTransportRequest =
                read_frame(&mut reader, original.len()).await.unwrap();
            assert!(decoded == frame);
            for limit in [0, original.len() - 1] {
                output.clear();
                let error = write_consensus_frame_bounded_until(
                    &mut output,
                    &frame,
                    limit,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
                .expect_err("unchanged ceiling before prefix");
                assert!(matches!(error, ProtocolError::FrameTooLarge(n) if n > limit));
                assert!(output.is_empty());
            }
            encoded_cases += 1;
        }
    }
    assert_eq!((encoded_cases, rejected_cases), (86, 4));
}

struct HaltAfterBytes<'a, W> {
    writer: W,
    cancellation: &'a AtomicBool,
    expire: bool,
    supplied: usize,
    largest: usize,
    armed: bool,
}

impl<W: std::io::Write> std::io::Write for HaltAfterBytes<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.supplied += bytes.len();
        self.largest = self.largest.max(bytes.len());
        let accepted = self.writer.write(bytes)?;
        if self.supplied >= 4096 && !self.armed {
            self.armed = true;
            if self.expire {
                tokio::time::resume();
                std::thread::sleep(Duration::from_millis(5));
            } else {
                self.cancellation.store(true, Ordering::Release);
            }
        }
        Ok(accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

fn check_numeric_array_halt(expire: bool) {
    use serde_json::ser::Formatter;

    let cancellation = AtomicBool::new(false);
    let control = EncodingControl {
        deadline: expire.then(|| tokio::time::Instant::now() + Duration::from_millis(1)),
        cancellation: &cancellation,
    };
    let mut sink = BoundedFrameBuffer::new(128 * 1024, control);
    let mut fragments = FrameFragmentBuffer::new(&mut sink);
    let mut writer = HaltAfterBytes {
        writer: &mut fragments,
        cancellation: &cancellation,
        expire,
        supplied: 0,
        largest: 0,
        armed: false,
    };
    let input = (0_u8..=255).cycle().take(32768).collect::<Vec<_>>();
    let error = consensus_json::NumericByteFormatter
        .write_byte_array(&mut writer, &input)
        .expect_err("bounded numeric emission must stop on the original sink halt");
    assert!(writer.armed);
    assert!(writer.largest <= 1024);
    assert!(writer.supplied <= 8192, "bounded work after the real halt");
    assert_eq!(
        error.kind(),
        if expire {
            std::io::ErrorKind::TimedOut
        } else {
            std::io::ErrorKind::Other
        }
    );
}

#[tokio::test]
async fn numeric_array_preserves_cooperative_cancellation() {
    check_numeric_array_halt(false);
}

#[tokio::test(start_paused = true)]
async fn numeric_array_preserves_original_cooperative_deadline() {
    check_numeric_array_halt(true);
}
