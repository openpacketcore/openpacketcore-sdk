#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::{
    decode_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    decode_ikev2_dedicated_bearer_delete_request, decode_ikev2_dedicated_bearer_delete_response,
    decode_ikev2_dedicated_bearer_informational_response,
    decode_ikev2_dedicated_bearer_modification_request, decode_ikev2_dedicated_bearer_notify,
    Header, HeaderFlags, Ikev2NotifyPayload, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_INFORMATIONAL,
};

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_seed(value: &[u8]) -> Option<Vec<u8>> {
    let digits = value
        .iter()
        .copied()
        .filter(|value| !value.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let mut chunks = digits.chunks_exact(2);
    let mut decoded = Vec::with_capacity(digits.len() / 2);
    for pair in &mut chunks {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    if chunks.remainder().is_empty() {
        Some(decoded)
    } else {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let decoded_seed = data.strip_prefix(b"hex:").and_then(decode_hex_seed);
    let data = decoded_seed.as_deref().unwrap_or(data);

    if let Ok(notify) = Ikev2NotifyPayload::decode_body(data) {
        let _ = decode_ikev2_dedicated_bearer_notify(notify);
    }

    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Some((&first_payload, cleartext_payloads)) = rest.split_first() else {
        return;
    };

    let mode = mode % 6;
    let is_response = matches!(mode, 1 | 4 | 5);
    let exchange_type = if mode <= 1 {
        EXCHANGE_TYPE_CREATE_CHILD_SA
    } else {
        EXCHANGE_TYPE_INFORMATIONAL
    };
    let header = Header::new(
        1,
        2,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(is_response, is_response, false),
        7,
    );
    let first_payload = PayloadType::from_u8(first_payload);

    match mode {
        0 => {
            let _ = decode_ikev2_dedicated_bearer_create_child_sa_request(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
        1 => {
            let _ = decode_ikev2_dedicated_bearer_create_child_sa_response(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
        2 => {
            let _ = decode_ikev2_dedicated_bearer_modification_request(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
        3 => {
            let _ = decode_ikev2_dedicated_bearer_delete_request(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
        4 => {
            let _ = decode_ikev2_dedicated_bearer_informational_response(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
        _ => {
            let _ = decode_ikev2_dedicated_bearer_delete_response(
                &header,
                first_payload,
                cleartext_payloads,
            );
        }
    }
});
