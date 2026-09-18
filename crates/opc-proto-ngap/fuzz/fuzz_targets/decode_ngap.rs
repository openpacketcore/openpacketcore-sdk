#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ngap::{encode, Criticality, MessageType, Pdu, ProtocolIe};
use opc_protocol::{
    DecodeContext, DuplicateIePolicy, Encode, EncodeContext, OwnedDecode, ValidationLevel,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 131072 {
        return;
    }
    let decode = DecodeContext {
        max_message_len: 200_000,
        max_ies: 32,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let output = EncodeContext {
        max_message_len: 200_000,
        ..EncodeContext::default()
    };
    if let Ok(pdu) = Pdu::decode_owned(Bytes::copy_from_slice(data), decode) {
        if let Ok(wire) = encode(&pdu, output) {
            assert_eq!(pdu.wire_len(output).unwrap(), wire.len());
            let received = Pdu::decode_owned(Bytes::from(wire), decode).unwrap();
            assert!(received.kind == pdu.kind);
        }
    }
    // Independent construction input: bounded borrowed chunks, including
    // repeated/unknown identifiers and opaque, potentially invalid leaf values.
    let ies: Vec<_> = data
        .chunks(256)
        .take(32)
        .filter(|chunk| chunk.len() >= 3)
        .map(|chunk| {
            let crit = match chunk[2] % 3 {
                0 => Criticality::reject,
                1 => Criticality::ignore,
                _ => Criticality::notify,
            };
            ProtocolIe::new(u16::from_be_bytes([chunk[0], chunk[1]]), crit, &chunk[3..])
        })
        .collect();
    let kind = match data.first().copied().unwrap_or(0) % 3 {
        0 => MessageType::NgSetupRequest,
        1 => MessageType::NgSetupResponse,
        _ => MessageType::NgSetupFailure,
    };
    for duplicate_ie_policy in [
        DuplicateIePolicy::First,
        DuplicateIePolicy::Last,
        DuplicateIePolicy::Reject,
    ] {
        if let Ok(pdu) = Pdu::from_protocol_ies(
            kind,
            &ies,
            DecodeContext {
                duplicate_ie_policy,
                ..decode
            },
        ) {
            let wire = encode(&pdu, output).unwrap();
            assert_eq!(pdu.wire_len(output).unwrap(), wire.len());
            assert!(Pdu::decode_owned(Bytes::from(wire), decode).unwrap().kind == pdu.kind);
        }
    }
    let large = Pdu::from_protocol_ies(
        kind,
        &[ProtocolIe::new(65535, Criticality::ignore, data)],
        decode,
    )
    .unwrap();
    let wire = encode(&large, output).unwrap();
    assert!(Pdu::decode_owned(Bytes::from(wire), decode).unwrap().kind == large.kind);
});
