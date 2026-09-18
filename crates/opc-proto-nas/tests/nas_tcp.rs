use opc_proto_nas::tcp::{NasTcpDecoder, NasTcpLimit};

#[test]
fn independent_three_octet_envelope_crosses_split_prefix() {
    let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
    let mut prefix = &[0][..];
    assert!(decoder.feed(&mut prefix).unwrap().is_none());
    assert!(prefix.is_empty());
    let mut suffix = &[3, 0x7e, 0, 0x41][..];
    let frame = decoder.feed(&mut suffix).unwrap().unwrap();
    assert_eq!(frame.payload(), &[0x7e, 0, 0x41]);
    assert!(suffix.is_empty());
    decoder.finish().unwrap();
}

use opc_proto_nas::tcp::{decode_envelope, encode_envelope, NasTcpError};

fn feed_chunks(
    stream: &[u8],
    ends: &[usize],
    bound: usize,
) -> (Vec<Vec<u8>>, Result<(), NasTcpError>) {
    let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(bound).unwrap());
    let mut frames = Vec::new();
    let mut start = 0;
    for &end in ends {
        let mut chunk = &stream[start..end];
        if chunk.is_empty() {
            assert!(decoder.feed(&mut chunk).unwrap().is_none());
        }
        while !chunk.is_empty() {
            let before = chunk.len();
            match decoder.feed(&mut chunk) {
                Ok(Some(frame)) => frames.push(frame.into_payload()),
                Ok(None) => assert!(chunk.is_empty()),
                Err(error) => return (frames, Err(error)),
            }
            assert!(chunk.len() < before);
        }
        start = end;
    }
    assert_eq!(start, stream.len());
    (frames, decoder.finish())
}

#[test]
fn every_partition_of_independent_coalesced_frames_preserves_order_and_bytes() {
    // Literal lengths count payload only. The unknown EPD is deliberate.
    let stream = [0, 3, 0x7e, 0, 0x41, 0, 2, 0x7f, 0xa5, 0, 1, 0xff];
    let expected = [vec![0x7e, 0, 0x41], vec![0x7f, 0xa5], vec![0xff]];
    for mask in 0..(1 << (stream.len() - 1)) {
        let mut ends = vec![0];
        ends.extend((1..stream.len()).filter(|i| mask & (1 << (i - 1)) != 0));
        ends.push(stream.len());
        let (frames, end) = feed_chunks(&stream, &ends, 3);
        assert!(frames == expected, "partition changed opaque frames");
        assert_eq!(end, Ok(()));
    }
}

#[test]
fn every_truncation_retains_completed_frames_and_finalizes_partial_input() {
    let stream = [0, 3, 0x7e, 0, 0x41, 0, 3, 0x7e, 0, 0x55];
    for end in 0..=stream.len() {
        for split in 0..=end {
            let (frames, finalized) = feed_chunks(&stream[..end], &[split, end], 256);
            assert_eq!(frames.len(), usize::from(end >= 5) + usize::from(end >= 10));
            if end >= 5 {
                assert!(frames[0] == [0x7e, 0, 0x41]);
            }
            if end == 10 {
                assert!(frames[1] == [0x7e, 0, 0x55]);
            }
            assert_eq!(
                finalized,
                if end % 5 == 0 {
                    Ok(())
                } else {
                    Err(NasTcpError::Truncated)
                }
            );
        }
    }
}

#[test]
fn complete_first_frame_does_not_admit_or_discard_its_trailing_frame() {
    let limit = NasTcpLimit::new(256).unwrap();
    for tail in [&[0][..], &[0, 5, 0x7e][..], &[0, 0][..], &[1, 1][..]] {
        let mut wire = vec![0, 3, 0x7e, 0, 0x41];
        wire.extend_from_slice(tail);
        let (first, rest) = decode_envelope(&wire, limit).unwrap().unwrap();
        assert!(first.payload() == [0x7e, 0, 0x41]);
        assert!(rest == tail);
        let mut input = wire.as_slice();
        let mut decoder = NasTcpDecoder::new(limit);
        let first = decoder.feed(&mut input).unwrap().unwrap();
        assert!(first.payload() == [0x7e, 0, 0x41]);
        assert!(input == tail);
        match decoder.feed(&mut input) {
            Ok(None) => assert_eq!(decoder.finish(), Err(NasTcpError::Truncated)),
            Err(error) => assert!(matches!(
                error,
                NasTcpError::EmptyPayload | NasTcpError::PayloadTooLarge
            )),
            Ok(Some(_)) => panic!("invalid tail unexpectedly yielded a frame"),
        }
    }
}

#[test]
fn every_length_prefix_obeys_inclusive_payload_bounds_before_body_arrival() {
    for bound in [1, 255, 256, 257, 65_535] {
        let limit = NasTcpLimit::new(bound).unwrap();
        for length in 0..=u16::MAX {
            let wire = length.to_be_bytes();
            let result = decode_envelope(&wire, limit);
            if length == 0 {
                assert_eq!(result.unwrap_err(), NasTcpError::EmptyPayload);
            } else if usize::from(length) > bound {
                assert_eq!(result.unwrap_err(), NasTcpError::PayloadTooLarge);
            } else {
                assert!(result.unwrap().is_none());
            }
        }
    }
}

#[test]
fn encode_is_exact_at_length_octet_boundaries_and_never_wraps() {
    let limit = NasTcpLimit::new(65_535).unwrap();
    for (length, prefix) in [
        (1, [0, 1]),
        (255, [0, 255]),
        (256, [1, 0]),
        (257, [1, 1]),
        (65_535, [255, 255]),
    ] {
        let payload = vec![0xb7; length];
        let mut encoded = vec![0xa5; length + 5];
        assert_eq!(
            encode_envelope(&payload, limit, &mut encoded).unwrap(),
            length + 2
        );
        assert!(encoded[..2] == prefix);
        assert!(encoded[2..length + 2] == payload);
        assert!(encoded[length + 2..] == [0xa5; 3]);
        let wire = &encoded[..length + 2];
        for split in [0, 1, 2, 3.min(wire.len()), wire.len() / 2, wire.len()] {
            let (frames, finalized) = feed_chunks(wire, &[split, wire.len()], length);
            assert!(frames == [payload.clone()]);
            assert_eq!(finalized, Ok(()));
        }
        let (frames, finalized) = feed_chunks(wire, &(1..=wire.len()).collect::<Vec<_>>(), length);
        assert!(frames == [payload]);
        assert_eq!(finalized, Ok(()));
    }
    let mut output = vec![0xa5; 65_538];
    assert_eq!(
        encode_envelope(&vec![0; 65_536], limit, &mut output),
        Err(NasTcpError::PayloadTooLarge)
    );
    assert!(output.iter().all(|&byte| byte == 0xa5));
}

#[test]
fn encode_refusals_leave_all_caller_storage_unchanged() {
    let limit = NasTcpLimit::new(3).unwrap();
    for (payload, error) in [
        (&[][..], NasTcpError::EmptyPayload),
        (&[1, 2, 3, 4][..], NasTcpError::PayloadTooLarge),
    ] {
        let mut output = [0xa5; 12];
        assert_eq!(encode_envelope(payload, limit, &mut output), Err(error));
        assert!(output == [0xa5; 12]);
    }
    for length in 0..5 {
        let mut storage = [0xa5; 12];
        assert_eq!(
            encode_envelope(&[0x7e, 0, 0x41], limit, &mut storage[..length]),
            Err(NasTcpError::OutputTooSmall)
        );
        assert!(storage == [0xa5; 12]);
    }
    for invalid in [0, 65_536, usize::MAX] {
        assert_eq!(
            NasTcpLimit::new(invalid).unwrap_err(),
            NasTcpError::InvalidLimit
        );
    }
}

#[test]
fn failed_and_finished_decoders_never_consume_more_input_or_resynchronize() {
    let limit = NasTcpLimit::new(256).unwrap();
    for (prefix, error) in [
        ([0, 0], NasTcpError::EmptyPayload),
        ([1, 1], NasTcpError::PayloadTooLarge),
    ] {
        let mut stream = prefix.to_vec();
        stream.extend_from_slice(&[0, 1, 0xff]);
        let mut input = stream.as_slice();
        let mut decoder = NasTcpDecoder::new(limit);
        assert_eq!(decoder.feed(&mut input).unwrap_err(), error);
        assert!(input == [0, 1, 0xff]);
        for _ in 0..3 {
            assert_eq!(decoder.feed(&mut input).unwrap_err(), error);
            assert!(input == [0, 1, 0xff]);
            assert_eq!(decoder.finish(), Err(error));
        }
    }
    let mut decoder = NasTcpDecoder::new(limit);
    decoder.finish().unwrap();
    decoder.finish().unwrap();
    let mut input = &[0, 1, 0xff][..];
    assert_eq!(decoder.feed(&mut input).unwrap_err(), NasTcpError::Finished);
    assert!(input == [0, 1, 0xff]);
    let mut truncated = NasTcpDecoder::new(limit);
    let mut partial = &[0, 1][..];
    assert!(truncated.feed(&mut partial).unwrap().is_none());
    assert_eq!(truncated.finish(), Err(NasTcpError::Truncated));
    assert_eq!(
        truncated.feed(&mut input).unwrap_err(),
        NasTcpError::Truncated
    );
    assert!(input == [0, 1, 0xff]);
    assert_eq!(truncated.finish(), Err(NasTcpError::Truncated));
}

#[test]
fn protected_and_unrecognized_nas_contents_remain_opaque_and_redacted() {
    let limit = NasTcpLimit::new(256).unwrap();
    for payload in [
        &[0x7e, 2, 0x11, 0x22, 0x33, 0x44, 9, 0xa5, 0x5a][..],
        &[0x7f, 0xff][..],
        b"nas-private-marker",
    ] {
        let mut wire = vec![0; payload.len() + 2];
        encode_envelope(payload, limit, &mut wire).unwrap();
        let (view, tail) = decode_envelope(&wire, limit).unwrap().unwrap();
        assert!(view.payload() == payload && tail.is_empty());
        assert_eq!(format!("{view:?}"), "NasTcpEnvelope(<redacted>)");
        let mut decoder = NasTcpDecoder::new(limit);
        let mut input = wire.as_slice();
        let owned = decoder.feed(&mut input).unwrap().unwrap();
        assert!(owned.payload() == payload);
        assert_eq!(format!("{owned:?}"), "NasTcpFrame(<redacted>)");
        assert_eq!(format!("{decoder:?}"), "NasTcpDecoder(<redacted>)");
    }
    assert_eq!(format!("{limit:?}"), "NasTcpLimit(<redacted>)");
    for error in [
        NasTcpError::InvalidLimit,
        NasTcpError::EmptyPayload,
        NasTcpError::PayloadTooLarge,
        NasTcpError::OutputTooSmall,
        NasTcpError::Truncated,
        NasTcpError::Finished,
        NasTcpError::AllocationFailed,
    ] {
        assert!(error.to_string().starts_with("nas_tcp_"));
        assert!(error.to_string().len() < 40);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn incomplete_and_invalid_prefixes_allocate_nothing_even_transiently() {
    for (prefix, error) in [
        ([0, 0], NasTcpError::EmptyPayload),
        ([1, 1], NasTcpError::PayloadTooLarge),
        ([255, 255], NasTcpError::PayloadTooLarge),
    ] {
        let stats = allocation_counter::measure(|| {
            let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
            let mut first = &prefix[..1];
            assert!(decoder.feed(&mut first).unwrap().is_none());
            let mut second = &prefix[1..];
            assert_eq!(decoder.feed(&mut second).unwrap_err(), error);
            assert_eq!(decoder.finish(), Err(error));
        });
        assert_eq!(stats.count_total, 0);
        assert_eq!(stats.bytes_total, 0);
    }
}

#[test]
fn allocation_tracks_one_declared_frame_and_is_released_on_end_or_drop() {
    let mut coalesced = vec![0, 3, 0x7f, 0xff, 0x41];
    coalesced.resize(1024 * 1024, 0x5a);
    let stats = allocation_counter::measure(|| {
        let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
        let mut input = coalesced.as_slice();
        let frame = decoder.feed(&mut input).unwrap().unwrap();
        assert!(frame.payload() == [0x7f, 0xff, 0x41]);
        assert_eq!(input.len(), coalesced.len() - 5);
        // Move the payload to prove there is no second allocation or copy.
        let payload = frame.into_payload();
        std::hint::black_box(&payload);
        drop(payload);
        decoder.finish().unwrap();
    });
    assert_eq!(stats.count_total, 1);
    assert_eq!(stats.bytes_total, 3);
    assert_eq!(stats.count_current, 0);
    assert_eq!(stats.bytes_current, 0);

    for finalize in [false, true] {
        let stats = allocation_counter::measure(|| {
            let mut decoder = NasTcpDecoder::new(NasTcpLimit::new(256).unwrap());
            let mut partial = &[1, 0, 0x7e][..];
            assert!(decoder.feed(&mut partial).unwrap().is_none());
            if finalize {
                assert_eq!(decoder.finish(), Err(NasTcpError::Truncated));
            }
            drop(decoder);
        });
        assert_eq!(stats.count_total, 1);
        assert_eq!(stats.bytes_total, 256);
        assert_eq!(stats.count_current, 0);
        assert_eq!(stats.bytes_current, 0);
    }
}

#[test]
fn borrowed_decode_and_caller_storage_encode_allocate_nothing() {
    let wire = [0, 3, 0x7f, 0xff, 0x41, 0];
    let mut output = [0xa5; 8];
    let stats = allocation_counter::measure(|| {
        let limit = NasTcpLimit::new(256).unwrap();
        let (view, tail) = decode_envelope(&wire, limit).unwrap().unwrap();
        assert_eq!(view.payload().as_ptr(), wire[2..].as_ptr());
        assert_eq!(tail.as_ptr(), wire[5..].as_ptr());
        assert_eq!(encode_envelope(view.payload(), limit, &mut output), Ok(5));
        assert!(output[..5] == wire[..5]);
        assert!(output[5..] == [0xa5; 3]);
    });
    assert_eq!(stats.count_total, 0);
    assert_eq!(stats.bytes_total, 0);
}
