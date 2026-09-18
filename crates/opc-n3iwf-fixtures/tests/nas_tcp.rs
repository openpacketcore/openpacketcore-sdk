//! Independent NAS/TCP streams exercise envelope framing without NAS decoding.
use opc_n3iwf_fixtures::{wire_digest, FixtureCatalog};
use opc_proto_nas::tcp::{
    decode_envelope, encode_envelope, NasTcpDecoder, NasTcpError, NasTcpLimit,
};

const REFERENCE: &str = include_str!("../../opc-proto-nas/tests/nas_tcp_reference.tsv");
const REFERENCE_SHA256: &str = "3a665814245476e584064a706b74d4b35be6bcb75ba20b7538d4a44a158c65f4";

fn hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn error_outcome(error: NasTcpError) -> &'static str {
    match error {
        NasTcpError::EmptyPayload => "empty",
        NasTcpError::PayloadTooLarge => "too-large",
        NasTcpError::Truncated => "truncated",
        _ => panic!("unexpected envelope refusal"),
    }
}

fn borrowed(mut stream: &[u8], limit: NasTcpLimit, closed: bool) -> (Vec<Vec<u8>>, &'static str) {
    let mut frames = Vec::new();
    while !stream.is_empty() {
        match decode_envelope(stream, limit) {
            Ok(Some((frame, tail))) => {
                frames.push(frame.payload().to_vec());
                stream = tail;
            }
            Ok(None) => {
                return (
                    frames,
                    if closed {
                        "truncated"
                    } else {
                        "need-more-data"
                    },
                )
            }
            Err(error) => return (frames, error_outcome(error)),
        }
    }
    (frames, "complete")
}

fn incremental(
    stream: &[u8],
    limit: NasTcpLimit,
    closed: bool,
    ends: &[usize],
) -> (Vec<Vec<u8>>, &'static str) {
    let mut decoder = NasTcpDecoder::new(limit);
    let mut frames = Vec::new();
    let mut start = 0;
    for &end in ends {
        let mut input = &stream[start..end];
        while !input.is_empty() {
            let before = input.len();
            match decoder.feed(&mut input) {
                Ok(Some(frame)) => frames.push(frame.into_payload()),
                Ok(None) => assert!(input.is_empty()),
                Err(error) => {
                    let retained = input;
                    assert_eq!(decoder.feed(&mut input).unwrap_err(), error);
                    assert!(input == retained);
                    assert_eq!(decoder.finish(), Err(error));
                    return (frames, error_outcome(error));
                }
            }
            assert!(input.len() < before);
        }
        start = end;
    }
    assert_eq!(start, stream.len());
    // Open partial input produced only Ok(None). Finalization observes whether
    // a partial frame remained, while the open-stream expectation stays need-more.
    let outcome = match decoder.finish() {
        Ok(()) => "complete",
        Err(NasTcpError::Truncated) if !closed => "need-more-data",
        Err(error) => error_outcome(error),
    };
    (frames, outcome)
}

fn check_stream(wire: &[u8], bound: usize, closed: bool, frames: &[Vec<u8>], outcome: &str) {
    let limit = NasTcpLimit::new(bound).unwrap();
    let actual = borrowed(wire, limit, closed);
    assert!(actual.0 == frames, "borrowed payload mismatch");
    assert_eq!(actual.1, outcome);
    let splits: Vec<_> = if wire.len() <= 64 {
        (0..=wire.len()).collect()
    } else {
        vec![0, 1, 2, wire.len() / 2, wire.len() - 1, wire.len()]
    };
    for split in splits {
        let actual = incremental(wire, limit, closed, &[split, wire.len()]);
        assert!(actual.0 == frames, "segmented payload mismatch");
        assert_eq!(actual.1, outcome);
    }
    let actual = incremental(wire, limit, closed, &(1..=wire.len()).collect::<Vec<_>>());
    assert!(actual.0 == frames, "byte-at-a-time payload mismatch");
    assert_eq!(actual.1, outcome);
    if outcome == "complete" {
        let mut encoded = Vec::new();
        for payload in frames {
            let mut frame = vec![0; payload.len() + 2];
            assert_eq!(
                encode_envelope(payload, limit, &mut frame).unwrap(),
                frame.len()
            );
            encoded.extend_from_slice(&frame);
        }
        assert!(encoded == wire, "independent canonical encoding mismatch");
    }
}

#[test]
fn independent_reference_streams_match_all_envelope_and_incremental_outcomes() {
    assert_eq!(wire_digest(REFERENCE.as_bytes()), REFERENCE_SHA256);
    let mut counts = [0; 5];
    for line in REFERENCE.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 6);
        let frames: Vec<_> = if fields[4] == "-" {
            Vec::new()
        } else {
            fields[4].split(',').map(hex).collect()
        };
        let index = [
            "complete",
            "need-more-data",
            "truncated",
            "empty",
            "too-large",
        ]
        .iter()
        .position(|&x| x == fields[3])
        .unwrap();
        counts[index] += 1;
        check_stream(
            &hex(fields[5]),
            fields[1].parse().unwrap(),
            fields[2] == "1",
            &frames,
            fields[3],
        );
    }
    assert_eq!(counts, [54, 46, 46, 8, 20]);
}

#[test]
fn every_reviewed_nas_tcp_fixture_exercises_its_declared_stream_boundary() {
    let catalog = FixtureCatalog::load().unwrap();
    let mut count = 0;
    for (manifest, wire) in catalog
        .manifests()
        .filter(|(manifest, _)| manifest.subset == "nas-tcp")
    {
        assert!(!manifest.runtime_claim);
        assert_eq!(manifest.validation_scope, "nas-tcp-envelope");
        let name = manifest.sdk_fixture_id.split(".v1.").nth(1).unwrap();
        let (frames, outcome): (Vec<Vec<u8>>, _) = match name {
            "positive-envelope" => (vec![hex("7e0041")], "complete"),
            "unknown-epd" => (vec![hex("7f0000")], "complete"),
            "duplicate-complete-frames" => (vec![hex("7e0041"), hex("7e0041")], "complete"),
            "ordering-two-message-types" => (vec![hex("7e0041"), hex("7e005d")], "complete"),
            "partial-need-more-data" | "truncated-length-octet" => (vec![], "need-more-data"),
            "eof-loss-incomplete-frame" => (vec![], "truncated"),
            "malformed-zero-length" => (vec![], "empty"),
            "bounded-length-overflow" => (vec![], "too-large"),
            _ => panic!("unclassified fixture"),
        };
        let bound = usize::try_from(manifest.context["max_payload_len"].as_u64().unwrap()).unwrap();
        assert_eq!(manifest.context["min_payload_len"], 1);
        check_stream(
            wire,
            bound,
            !manifest.context["stream_open"].as_bool().unwrap(),
            &frames,
            outcome,
        );
        count += 1;
    }
    assert_eq!(count, 9);
}
