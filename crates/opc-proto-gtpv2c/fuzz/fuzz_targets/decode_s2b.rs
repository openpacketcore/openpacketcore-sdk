#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, MessageDirection, Procedure, S2bMessage,
};
use opc_protocol::{DecodeContext, ValidationLevel};

// Textual hex keeps these small protocol seeds reviewable in ordinary diffs.
// Ordinary fuzzer inputs remain raw bytes; only the explicit `hex:` corpus
// form is decoded here.
fn decode_hex_seed(data: &[u8]) -> Option<Vec<u8>> {
    const MAX_SEED_BYTES: usize = 4_096;

    let encoded = data.strip_prefix(b"hex:")?;
    let encoded = encoded.strip_suffix(b"\n").unwrap_or(encoded);
    let encoded = encoded.strip_suffix(b"\r").unwrap_or(encoded);
    if encoded.len() > MAX_SEED_BYTES * 2 || encoded.len() % 2 != 0 {
        return None;
    }

    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let decoded_seed = decode_hex_seed(data);
    let data = decoded_seed.as_deref().unwrap_or(data);

    let _ = S2bMessage::decode(data, DecodeContext::default());

    let procedure = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    if let Ok((_tail, message)) = S2bMessage::decode(data, procedure) {
        if let Some(view) = message.as_view() {
            if view.procedure == Procedure::ModifyBearer
                && view.direction == MessageDirection::Request
            {
                let _ = view.ue_ipsec_tunnel_update_request_summary();
            }
            if view.procedure == Procedure::CreateSession
                && view.direction == MessageDirection::Request
            {
                let _ = view.create_session_context();
            }
            if view.procedure == Procedure::DeleteSession
                && view.direction == MessageDirection::Request
            {
                let _ = view.delete_session_context();
            }
        }
    }

    let shallow = DecodeContext {
        max_depth: 2,
        max_ies: 4,
        ..DecodeContext::default()
    };
    let _ = decode_typed_ie_sequence(data, shallow, 0);
});
