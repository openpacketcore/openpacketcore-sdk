#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_nas::tcp::{
    decode_envelope, encode_envelope, NasTcpDecoder, NasTcpError, NasTcpLimit,
};

fn reference(mut input: &[u8], limit: usize) -> (Vec<&[u8]>, Result<(), NasTcpError>) {
    let mut frames = Vec::new();
    while !input.is_empty() {
        if input.len() < 2 {
            return (frames, Err(NasTcpError::Truncated));
        }
        let size = usize::from(input[0]) * 256 + usize::from(input[1]);
        if size == 0 {
            return (frames, Err(NasTcpError::EmptyPayload));
        }
        if size > limit {
            return (frames, Err(NasTcpError::PayloadTooLarge));
        }
        if input.len() - 2 < size {
            return (frames, Err(NasTcpError::Truncated));
        }
        frames.push(&input[2..2 + size]);
        input = &input[2 + size..];
    }
    (frames, Ok(()))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 4096 {
        return;
    }
    let bound = usize::from(data[0]) * 256 + usize::from(data[1]);
    let limit = NasTcpLimit::new(bound);
    if bound == 0 {
        assert_eq!(limit.unwrap_err(), NasTcpError::InvalidLimit);
        return;
    }
    let limit = limit.unwrap();
    let wire = &data[4..];
    // Odd control values terminate early, modelling cancellation/loss/EOF at
    // every possible prefix/body boundary; even values retain the whole input.
    let wire = if data[2] & 1 == 1 {
        &wire[..(usize::from(data[2] / 2) * 256 + usize::from(data[3])) % (wire.len() + 1)]
    } else {
        wire
    };
    let (expected, outcome) = reference(wire, bound);
    let mut decoder = NasTcpDecoder::new(limit);
    let mut actual = Vec::new();
    let mut failure = None;
    for chunk in wire.chunks(usize::from(data[3]) + 1) {
        let mut input = chunk;
        while !input.is_empty() {
            let before = input.len();
            match decoder.feed(&mut input) {
                Ok(Some(frame)) => {
                    assert_eq!(format!("{frame:?}"), "NasTcpFrame(<redacted>)");
                    let mut encoded = vec![0xa5; frame.payload().len() + 3];
                    let length = encode_envelope(frame.payload(), limit, &mut encoded).unwrap();
                    assert_eq!(encoded[length], 0xa5);
                    assert_eq!(
                        usize::from(encoded[0]) * 256 + usize::from(encoded[1]),
                        frame.payload().len()
                    );
                    let (view, tail) = decode_envelope(&encoded[..length], limit).unwrap().unwrap();
                    assert!(view.payload() == frame.payload() && tail.is_empty());
                    actual.push(frame.into_payload());
                }
                Ok(None) => assert!(input.is_empty()),
                Err(error) => {
                    let rest = input;
                    assert_eq!(decoder.feed(&mut input).unwrap_err(), error);
                    assert!(input == rest);
                    failure = Some(error);
                    break;
                }
            }
            assert!(input.len() < before);
        }
        if failure.is_some() {
            break;
        }
        let mut empty = &[][..];
        assert!(decoder.feed(&mut empty).unwrap().is_none());
    }
    assert!(actual.iter().map(Vec::as_slice).eq(expected));
    let end = decoder.finish();
    assert_eq!(failure.map_or(end, Err), outcome);
    assert_eq!(decoder.finish(), end);
    let mut late = &[0, 1, 0xff][..];
    assert_eq!(
        decoder.feed(&mut late).unwrap_err(),
        end.err().unwrap_or(NasTcpError::Finished)
    );
    assert!(late == [0, 1, 0xff]);
    assert_eq!(format!("{decoder:?}"), "NasTcpDecoder(<redacted>)");
});
